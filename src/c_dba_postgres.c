/***********************************************************************
 *          C_DBA_POSTGRES.C
 *          Dba_postgres GClass.
 *
 *          DBA Dba_postgres
 *
 *          Copyright (c) 2021 by Niyamaka.
 *          All Rights Reserved.
 ***********************************************************************/
#include <string.h>
#include <stdio.h>
#include "c_dba_postgres.h"

#include "treedb_schema_dba_postgres.c"

/***************************************************************************
 *              Constants
 ***************************************************************************/

/***************************************************************************
 *              Structures
 ***************************************************************************/

/***************************************************************************
 *              Prototypes
 ***************************************************************************/

/***************************************************************************
 *          Data: config, public data, private data
 ***************************************************************************/
PRIVATE topic_desc_t db_dba_postgres_desc[] = {
    // Topic Name,          Pkey            System Flag     Tkey        Topic Json Desc
    {"raw_tracks",          "id",           sf_string_key,  "tm",       0},
    {0}
};

PRIVATE json_t *cmd_help(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_authzs(hgobj gobj, const char *cmd, json_t *kw, hgobj src);

PRIVATE sdata_desc_t pm_help[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "cmd",          0,              0,          "command about you want help."),
SDATAPM (ASN_UNSIGNED,  "level",        0,              0,          "command search level in childs"),
SDATA_END()
};
PRIVATE sdata_desc_t pm_authzs[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "authz",        0,              0,          "authz about you want help"),
SDATA_END()
};

PRIVATE const char *a_help[] = {"h", "?", 0};

PRIVATE sdata_desc_t command_table[] = {
/*-CMD---type-----------name----------------alias-------items-------json_fn---------description--*/
SDATACM (ASN_SCHEMA,    "help",             a_help,     pm_help,    cmd_help,       "Command's help"),
SDATACM (ASN_SCHEMA,    "authzs",           0,          pm_authzs,  cmd_authzs,     "Authorization's help"),
SDATA_END()
};


/*---------------------------------------------*
 *      Attributes - order affect to oid's
 *---------------------------------------------*/
PRIVATE sdata_desc_t tattr_desc[] = {
/*-ATTR-type------------name------------flag--------------------default-----description--*/
SDATA (ASN_COUNTER64,   "txMsgs",       SDF_RD|SDF_RSTATS,      0,          "Messages transmitted"),
SDATA (ASN_COUNTER64,   "rxMsgs",       SDF_RD|SDF_RSTATS,      0,          "Messages receiveds"),

SDATA (ASN_COUNTER64,   "txMsgsec",     SDF_RD|SDF_RSTATS,      0,          "Messages by second"),
SDATA (ASN_COUNTER64,   "rxMsgsec",     SDF_RD|SDF_RSTATS,      0,          "Messages by second"),
SDATA (ASN_COUNTER64,   "maxtxMsgsec",  SDF_WR|SDF_RSTATS,      0,          "Max Tx Messages by second"),
SDATA (ASN_COUNTER64,   "maxrxMsgsec",  SDF_WR|SDF_RSTATS,      0,          "Max Rx Messages by second"),

SDATA (ASN_BOOLEAN,     "enabled_new_devices",SDF_WR,           1,          "Auto enable new devices"),
SDATA (ASN_INTEGER,     "timeout",      SDF_RD,                 1*1000,     "Timeout"),
SDATA (ASN_POINTER,     "user_data",    0,                      0,          "user data"),
SDATA (ASN_POINTER,     "user_data2",   0,                      0,          "more user data"),
SDATA_END()
};

/*---------------------------------------------*
 *      GClass trace levels
 *---------------------------------------------*/
enum {
    TRACE_MESSAGES  = 0x0001,
};
PRIVATE const trace_level_t s_user_trace_level[16] = {
{"messages",        "Trace messages"},
{0, 0},
};

/*---------------------------------------------*
 *      GClass authz levels
 *---------------------------------------------*/
PRIVATE sdata_desc_t pm_authz_create[] = {
/*-PM-----type--------------name----------------flag--------authpath--------description-- */
SDATAPM0 (ASN_OCTET_STR,    "topic_name",       0,          "",             "Topic name"),
SDATA_END()
};
PRIVATE sdata_desc_t pm_authz_update[] = {
/*-PM-----type--------------name----------------flag--------authpath--------description-- */
SDATAPM0 (ASN_OCTET_STR,    "topic_name",       0,          "",             "Topic name"),
SDATAPM0 (ASN_OCTET_STR,    "id",               0,          "",             "Id"),
SDATA_END()
};
PRIVATE sdata_desc_t pm_authz_read[] = {
/*-PM-----type--------------name----------------flag--------authpath--------description-- */
SDATAPM0 (ASN_OCTET_STR,    "topic_name",       0,          "",             "Topic name"),
SDATAPM0 (ASN_OCTET_STR,    "id",               0,          "",             "Id"),
SDATA_END()
};
PRIVATE sdata_desc_t pm_authz_delete[] = {
/*-PM-----type--------------name----------------flag--------authpath--------description-- */
SDATAPM0 (ASN_OCTET_STR,    "topic_name",       0,          "",             "Topic name"),
SDATAPM0 (ASN_OCTET_STR,    "id",               0,          "",             "Id"),
SDATA_END()
};

PRIVATE sdata_desc_t authz_table[] = {
/*-AUTHZ-- type---------name------------flag----alias---items---------------description--*/
SDATAAUTHZ (ASN_SCHEMA, "create",       0,      0,      pm_authz_create,    "Permission to create"),
SDATAAUTHZ (ASN_SCHEMA, "update",       0,      0,      pm_authz_update,    "Permission to update"),
SDATAAUTHZ (ASN_SCHEMA, "read",         0,      0,      pm_authz_read,      "Permission to read"),
SDATAAUTHZ (ASN_SCHEMA, "delete",       0,      0,      pm_authz_delete,    "Permission to delete"),
SDATA_END()
};

/*---------------------------------------------*
 *              Private data
 *---------------------------------------------*/
typedef struct _PRIVATE_DATA {
    int32_t timeout;
    hgobj timer;

    hgobj gobj_input_side;
    hgobj gobj_top_side;

    hgobj treedb_dba_postgres;
    hgobj gobj_tranger;
    json_t *tranger;

    json_t *tracks;

    uint64_t *ptxMsgs;
    uint64_t *prxMsgs;
    uint64_t txMsgsec;
    uint64_t rxMsgsec;
} PRIVATE_DATA;




            /******************************
             *      Framework Methods
             ******************************/




/***************************************************************************
 *      Framework Method create
 ***************************************************************************/
PRIVATE void mt_create(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    helper_quote2doublequote(treedb_schema_dba_postgres);

    /*
     *  Chequea schema fichador, exit si falla.
     */
    json_t *jn_treedb_schema_dba_postgres;
    jn_treedb_schema_dba_postgres = legalstring2json(treedb_schema_dba_postgres, TRUE);
    if(!jn_treedb_schema_dba_postgres) {
        exit(-1);
    }

    priv->timer = gobj_create(gobj_name(gobj), GCLASS_TIMER, 0, gobj);
    priv->ptxMsgs = gobj_danger_attr_ptr(gobj, "txMsgs");
    priv->prxMsgs = gobj_danger_attr_ptr(gobj, "rxMsgs");

    /*---------------------------*
     *  Create Timeranger
     *---------------------------*/
    char path[PATH_MAX];
    if(!yuneta_realm_store_dir(
        path,
        sizeof(path),
        "dba_postgres",
        gobj_yuno_realm_owner(),
        gobj_yuno_realm_id(),
        "treedb",
        TRUE
    )) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "Check configuration, empty or without access",
            NULL
        );
    }

    json_t *kw_tranger = json_pack("{s:s, s:s, s:b, s:i}",
        "path", path,
        "filename_mask", "%Y-%m-%d",
        "master", 1,
        "on_critical_error", (int)(LOG_OPT_EXIT_ZERO)
    );
    priv->gobj_tranger = gobj_create_service(
        "tranger_dba_postgres",
        GCLASS_TRANGER,
        kw_tranger,
        gobj
    );

    /*----------------------*
     *  Create Treedb
     *----------------------*/
    const char *treedb_name = kw_get_str(
        jn_treedb_schema_dba_postgres,
        "id",
        "treedb_dba_postgres",
        KW_REQUIRED
    );
    json_t *kw_resource = json_pack("{s:s, s:o, s:i}",
        "treedb_name", treedb_name,
        "treedb_schema", jn_treedb_schema_dba_postgres,
        "exit_on_error", LOG_OPT_EXIT_ZERO
    );

    priv->treedb_dba_postgres = gobj_create_service(
        treedb_name,
        GCLASS_NODE,
        kw_resource,
        gobj
    );

    /*
     *  HACK pipe inheritance
     */
    gobj_set_bottom_gobj(priv->treedb_dba_postgres, priv->gobj_tranger);
    gobj_set_bottom_gobj(gobj, priv->treedb_dba_postgres);

    /*
     *  Do copy of heavy used parameters, for quick access.
     *  HACK The writable attributes must be repeated in mt_writing method.
     */
    SET_PRIV(timeout,               gobj_read_int32_attr)
}

/***************************************************************************
 *      Framework Method writing
 ***************************************************************************/
PRIVATE void mt_writing(hgobj gobj, const char *path)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    IF_EQ_SET_PRIV(timeout,         gobj_read_int32_attr)
    END_EQ_SET_PRIV()
}

/***************************************************************************
 *      Framework Method destroy
 ***************************************************************************/
PRIVATE void mt_destroy(hgobj gobj)
{
}

/***************************************************************************
 *      Framework Method start
 ***************************************************************************/
PRIVATE int mt_start(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    gobj_start(priv->timer);

    return 0;
}

/***************************************************************************
 *      Framework Method stop
 ***************************************************************************/
PRIVATE int mt_stop(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    gobj_stop(priv->timer);

    return 0;
}

/***************************************************************************
 *      Framework Method play
 *  Yuneta rule:
 *  If service has mt_play then start only the service gobj.
 *      (Let mt_play be responsible to start their tree)
 *  If service has not mt_play then start the tree with gobj_start_tree().
 ***************************************************************************/
PRIVATE int mt_play(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    /*
     *  Start tranger/treedb
     */
    if(!gobj_is_running(priv->treedb_dba_postgres)) {
        gobj_start(priv->treedb_dba_postgres);
    }

    /*
     *  HACK pipe inheritance
     */
    priv->tranger = gobj_read_pointer_attr(gobj, "tranger");

    /*
     *  Start services
     */
    priv->gobj_input_side = gobj_find_service("__input_side__", TRUE);
    gobj_subscribe_event(priv->gobj_input_side, 0, 0, gobj);

    priv->gobj_top_side = gobj_find_service("__top_side__", TRUE);
    gobj_subscribe_event(priv->gobj_top_side, 0, 0, gobj);

    gobj_start_tree(priv->gobj_input_side);
    gobj_start_tree(priv->gobj_top_side);

    if(1) {
        /*---------------------------*
         *  Open topics as messages
         *---------------------------*/
        trmsg_open_topics(
            priv->tranger,
            db_dba_postgres_desc
        );

        /*
         *  To open tracks
         *  TODO abre temporalmente un trace general,
         *  pero estos hay que pasarlos a cada user
         */
        priv->tracks = trmsg_open_list(
            priv->tranger,
            "raw_tracks",  // topic
            json_pack("{s:i}",  // filter
                "max_key_instances", 10
            )
        );
    }

    /*
     *  Periodic timer for tasks
     */
    set_timeout_periodic(priv->timer, priv->timeout);

    return 0;
}

/***************************************************************************
 *      Framework Method pause
 ***************************************************************************/
PRIVATE int mt_pause(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    /*
     *  Stop services
     */
    gobj_unsubscribe_event(priv->gobj_top_side, 0, 0, gobj);
    EXEC_AND_RESET(gobj_stop_tree, priv->gobj_top_side);

    gobj_unsubscribe_event(priv->gobj_input_side, 0, 0, gobj);
    EXEC_AND_RESET(gobj_stop_tree, priv->gobj_input_side);

    /*
     *  Stop treeb/tranger
     */
    gobj_stop(priv->treedb_dba_postgres);
    priv->tranger = 0;

    clear_timeout(priv->timer);

    return 0;
}

/***************************************************************************
 *      Framework Method subscription_added
 ***************************************************************************/
PRIVATE int mt_subscription_added(
    hgobj gobj,
    hsdata subs)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    json_t *__config__ = sdata_read_json(subs, "__config__");
    BOOL first_shot = kw_get_bool(__config__, "__first_shot__", TRUE, 0);
    if(!first_shot) {
        return 0;
    }

    const char *event = sdata_read_str(subs, "event");
    json_t *__global__ = sdata_read_json(subs, "__global__");

    if(strcasecmp(event, "EV_REALTIME_TRACK")==0) {
        json_t *__filter__ = sdata_read_json(subs, "__filter__");
        //json_t *__config__ = sdata_read_json(subs, "__config__");
        hgobj subscriber = sdata_read_pointer(subs, "subscriber");

        json_t *jn_comment = 0;
        int result = 0;
        json_t *jn_data = 0;

        /*----------------------------------------*
         *  Check AUTHZS
         *----------------------------------------*/
        const char *permission = "read";
        if(gobj_user_has_authz(gobj, permission, 0, subscriber)) {
            // TODO crea la lista en el user
            JSON_INCREF(__filter__);
            jn_data = trmsg_active_records(priv->tracks, __filter__);
        } else {
            jn_comment = json_sprintf("No permission to '%s'", permission);
            result = -1;
        }

        /*
         *  Inform
         */
        return gobj_send_event(
            subscriber,
            event,
            msg_iev_build_webix2_without_answer_filter(gobj,
                result,
                jn_comment,
                0, //RESOURCE_WEBIX_SCHEMA(priv->resource, resource),
                jn_data, // owned
                __global__?kw_duplicate(__global__):0,  // owned
                "__first_shot__"
            ),
            gobj
        );
    }

    return 0;
}




            /***************************
             *      Commands
             ***************************/




/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_help(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    KW_INCREF(kw);
    json_t *jn_resp = gobj_build_cmds_doc(gobj, kw);
    return msg_iev_build_webix(
        gobj,
        0,
        jn_resp,
        0,
        0,
        kw  // owned
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_authzs(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    return gobj_build_authzs_doc(gobj, cmd, kw, src);
}




            /***************************
             *      Local Methods
             ***************************/




/***************************************************************************
 *  Send ack to __input_side__
 ***************************************************************************/
PRIVATE int send_ack(
    hgobj gobj,
    json_t *kw_ack,  // owned
    json_t *__temp__ // channel info
)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(gobj_trace_level(gobj) & TRACE_MESSAGES) {
        log_debug_json(LOG_DUMP_OUTPUT, kw_ack, "%s ==> %s", gobj_short_name(gobj), gobj_short_name(priv->gobj_input_side));
    }

    GBUFFER *gbuf = json2gbuf(0, kw_ack, JSON_COMPACT);
    json_t *kw_send = json_pack("{s:I}",
        "gbuffer", (json_int_t)(size_t)gbuf
    );

    json_object_set_new(kw_send, "__temp__", __temp__);  // Set the channel

    return gobj_send_event(priv->gobj_input_side, "EV_SEND_MESSAGE", kw_send, gobj);
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *build_track_message(
    hgobj gobj,
    json_t *device,
    json_t *kw  // NOT owned
)
{
    static const json_desc_t track_json_desc[] = {
    // Name                 Type    Default
    {"id",                  "str",  ""},
    {"event",               "str",  "trace"},
    {"tm",                  "int",  "0"},
    // TODO add your device fields
    {0}
    };

    json_t *msg = create_json_record(track_json_desc);
    json_object_update_existing(msg, kw);

    json_object_set_new(
        msg,
        "name",
        json_string(kw_get_str(device, "name", "", KW_REQUIRED))
    );

    return msg;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int process_msg(
    hgobj gobj,
    json_t *kw,  // NOT owned
    hgobj src
)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    const char *id = kw_get_str(kw, "id", "", KW_REQUIRED);
    if(empty_string(id)) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "Message without id",
            NULL
        );
        log_debug_json(0, kw, "Message without id");
        return 0; // que devuelva ack para que borre el msg
    }

    /*--------------------------------*
     *  Get device of track
     *  Create it if not exist
     *--------------------------------*/
    json_t *device = gobj_get_node(
        priv->treedb_dba_postgres,
        "devices",
        json_incref(kw),
        0,
        src
    );
    if(!device) {
        time_t t;
        time(&t);
        BOOL enabled_new_devices = gobj_read_bool_attr(gobj, "enabled_new_devices");
        json_t *jn_properties = json_incref(kw_get_dict(kw, "properties", 0, 0));
        if(!jn_properties) {
            jn_properties = json_object();
        }

        json_t *jn_device = json_pack("{s:s, s:s, s:b, s:o, s:s, s:I}",
            "id", id,
            "name", kw_get_str(kw, "name", "", 0),
            "enabled", enabled_new_devices,
            "properties", jn_properties,
            "yuno", kw_get_str(kw, "yuno", "", 0),
            "time", (json_int_t)t
        );
        device = gobj_create_node(
            priv->treedb_dba_postgres,
            "devices",
            jn_device,
            0,
            src
        );
    }

    /*--------------------------------*
     *      Save the message
     *--------------------------------*/
    json_t *msg = build_track_message(
        gobj,
        device,
        kw  // not owned
    );

    int ret = trmsg_add_instance(
        priv->tranger,
        "raw_tracks",
        json_incref(msg),
        0,
        0
    );
    JSON_DECREF(device);

    /*--------------------------------*
     *      Publish the trace
     *--------------------------------*/
    json_t * kw2publish = msg_iev_build_webix2(
        gobj,
        0,
        0,
        0,
        msg, // owned
        0,
        "__publishing__"
    );
    gobj_publish_event(gobj, "EV_REALTIME_TRACK", kw2publish);

    return ret;
}




            /***************************
             *      Actions
             ***************************/




/***************************************************************************
 *  Identity_card on from
 *      Web clients (__top_side__)
 *  Connection from
 *      Input gates (__input_side__)
 ***************************************************************************/
PRIVATE int ac_on_open(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(src == priv->gobj_top_side) {
        // User connected
    } else if(src == priv->gobj_input_side) {

    } else {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "What fuck from?",
            "src",          "%s", gobj_full_name(src),
            NULL
        );
    }

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *  Identity_card off from
 *      Web clients (__top_side__)
 *  Disconnection from
 *      Input gates (__input_side__)
 ***************************************************************************/
PRIVATE int ac_on_close(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(src == priv->gobj_top_side) {

    } else if(src == priv->gobj_input_side) {

    } else {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "What fuck from?",
            "src",          "%s", gobj_full_name(src),
            NULL
        );
    }

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *  Message from input gates
 ***************************************************************************/
PRIVATE int ac_on_message(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    int ret = 0;

    (*priv->prxMsgs)++;
    priv->rxMsgsec++;

    if(src == priv->gobj_input_side ) {
        GBUFFER *gbuf = (GBUFFER *)(size_t)kw_get_int(kw, "gbuffer", 0, 0);

        gbuf_incref(gbuf);
        json_t *jn_msg = gbuf2json(gbuf, 2);

        if(jn_msg) {
            hgobj channel_gobj = (hgobj)(size_t)kw_get_int(kw, "__temp__`channel_gobj", 0, KW_REQUIRED);
            if(gobj_trace_level(gobj) & TRACE_MESSAGES) {
                log_debug_json(LOG_DUMP_INPUT, jn_msg, "%s <== %s <== %s",
                    gobj_short_name(gobj),
                    gobj_short_name(src),
                    gobj_short_name(channel_gobj)
                );
            }

            ret = process_msg(gobj, jn_msg, src);
            if(ret == 0) {
                json_t *__temp__ = kw_get_dict_value(kw, "__temp__", 0, KW_REQUIRED|KW_EXTRACT);

                json_t *kw_ack = trq_answer(
                    jn_msg,  // not owned
                    0
                );

                if(gobj_trace_level(gobj) & TRACE_MESSAGES) {
                    trace_msg("  -> BACK ack rowid %"JSON_INTEGER_FORMAT"",
                        kw_get_int(kw_ack, __MD_TRQ__"`__msg_key__", 0, KW_REQUIRED)
                    );
                }
                send_ack(
                    gobj,
                    kw_ack, // owned
                    __temp__ // Set the channel
                );
            }
            JSON_DECREF(jn_msg);
        } else {
            ret = -1;
        }
    } else if(src == priv->gobj_top_side) {

    } else {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "What fuck from?",
            "src",          "%s", gobj_full_name(src),
            NULL
        );
    }


    KW_DECREF(kw);
    return ret;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_list_tracks(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    json_t *__temp__ = kw_get_dict_value(kw, "__temp__", 0, KW_REQUIRED|KW_EXTRACT);

    int result = 0;
    json_t *jn_data = 0;
    json_t *jn_comment = 0;

    do {
        /*----------------------------------------*
         *  Check AUTHZS
         *----------------------------------------*/
        const char *permission = "read";
        if(!gobj_user_has_authz(gobj, permission, kw_incref(kw), src)) {
            jn_comment = json_sprintf("No permission to '%s'", permission);
            result = -1;
            break;
        }

        /*
         *  Get track list
         */
        KW_INCREF(kw);
        json_t *list = trmsg_open_list(
            priv->tranger,
            "raw_tracks",
            kw
        );
        // WARNING aquí no podemos aplicar kw como filtro,
        // tendría que venir dentro de kw en una key tipo "filter" de tercer nivel
        jn_data = trmsg_data_tree(list, 0);

        trmsg_close_list(priv->tranger, list);

    } while(0);

    /*
     *  Response
     */
    json_t *iev = iev_create(
        event,
        msg_iev_build_webix2(gobj,
            result,
            jn_comment,
            0,
            jn_data?jn_data:json_array(),  // owned
            kw,  // owned
            "__answer__"
        )
    );
    json_object_set_new(iev, "__temp__", __temp__);  // Set the channel

    /*
     *  Inform
     */
    return gobj_send_event(
        src,
        "EV_SEND_IEV",
        iev,
        gobj
    );
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_timeout(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    uint64_t maxtxMsgsec = gobj_read_uint64_attr(gobj, "maxtxMsgsec");
    uint64_t maxrxMsgsec = gobj_read_uint64_attr(gobj, "maxrxMsgsec");
    if(priv->txMsgsec > maxtxMsgsec) {
        gobj_write_uint64_attr(gobj, "maxtxMsgsec", priv->txMsgsec);
    }
    if(priv->rxMsgsec > maxrxMsgsec) {
        gobj_write_uint64_attr(gobj, "maxrxMsgsec", priv->rxMsgsec);
    }

    gobj_write_uint64_attr(gobj, "txMsgsec", priv->txMsgsec);
    gobj_write_uint64_attr(gobj, "rxMsgsec", priv->rxMsgsec);

    priv->rxMsgsec = 0;
    priv->txMsgsec = 0;

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *                          FSM
 ***************************************************************************/
PRIVATE const EVENT input_events[] = {
    // top input
    {"EV_ON_MESSAGE",       0,  0,  0},
    {"EV_LIST_TRACKS",      EVF_PUBLIC_EVENT,  0,  0},

    {"EV_ON_OPEN",          0,  0,  0},
    {"EV_ON_CLOSE",         0,  0,  0},
    // bottom input
    {"EV_TIMEOUT",          0,  0,  0},
    {"EV_STOPPED",          0,  0,  0},
    // internal
    {NULL, 0, 0, ""}
};
PRIVATE const EVENT output_events[] = {
    {"EV_LIST_TRACKS",      EVF_PUBLIC_EVENT,  0,  0},
    {"EV_REALTIME_TRACK",   EVF_PUBLIC_EVENT,  0,  0}, // old EV_DEVICE_TRACE
    {NULL, 0, 0, ""}
};
PRIVATE const char *state_names[] = {
    "ST_IDLE",
    NULL
};

PRIVATE EV_ACTION ST_IDLE[] = {
    {"EV_ON_MESSAGE",       ac_on_message,      0},
    {"EV_LIST_TRACKS",      ac_list_tracks,    0},
    {"EV_ON_OPEN",          ac_on_open,         0},
    {"EV_ON_CLOSE",         ac_on_close,        0},
    {"EV_TIMEOUT",          ac_timeout,         0},
    {"EV_STOPPED",          0,                  0},
    {0,0,0}
};

PRIVATE EV_ACTION *states[] = {
    ST_IDLE,
    NULL
};

PRIVATE FSM fsm = {
    input_events,
    output_events,
    state_names,
    states,
};

/***************************************************************************
 *              GClass
 ***************************************************************************/
/*---------------------------------------------*
 *              Local methods table
 *---------------------------------------------*/
PRIVATE LMETHOD lmt[] = {
    {0, 0, 0}
};

/*---------------------------------------------*
 *              GClass
 *---------------------------------------------*/
PRIVATE GCLASS _gclass = {
    0,  // base
    GCLASS_DBA_POSTGRES_NAME,
    &fsm,
    {
        mt_create,
        0, //mt_create2,
        mt_destroy,
        mt_start,
        mt_stop,
        mt_play,
        mt_pause,
        mt_writing,
        0, //mt_reading,
        mt_subscription_added,
        0, //mt_subscription_deleted,
        0, //mt_child_added,
        0, //mt_child_removed,
        0, //mt_stats,
        0, //mt_command_parser,
        0, //mt_inject_event,
        0, //mt_create_resource,
        0, //mt_list_resource,
        0, //mt_update_resource,
        0, //mt_delete_resource,
        0, //mt_add_child_resource_link
        0, //mt_delete_child_resource_link
        0, //mt_get_resource
        0, //mt_future24,
        0, //mt_authenticate,
        0, //mt_list_childs,
        0, //mt_stats_updated,
        0, //mt_disable,
        0, //mt_enable,
        0, //mt_trace_on,
        0, //mt_trace_off,
        0, //mt_gobj_created,
        0, //mt_future33,
        0, //mt_future34,
        0, //mt_publish_event,
        0, //mt_publication_pre_filter,
        0, //mt_publication_filter,
        0, //mt_authz_checker,
        0, //mt_future39,
        0, //mt_create_node,
        0, //mt_update_node,
        0, //mt_delete_node,
        0, //mt_link_nodes,
        0, //mt_future44,
        0, //mt_unlink_nodes,
        0, //mt_future46,
        0, //mt_get_node,
        0, //mt_list_nodes,
        0, //mt_shoot_snap,
        0, //mt_activate_snap,
        0, //mt_list_snaps,
        0, //mt_treedbs,
        0, //mt_treedb_topics,
        0, //mt_topic_desc,
        0, //mt_topic_links,
        0, //mt_topic_hooks,
        0, //mt_node_parents,
        0, //mt_node_childs,
        0, //mt_list_instances,
        0, //mt_future60,
        0, //mt_topic_size,
        0, //mt_future62,
        0, //mt_future63,
        0, //mt_future64
    },
    lmt,
    tattr_desc,
    sizeof(PRIVATE_DATA),
    authz_table,  // acl
    s_user_trace_level,
    command_table,  // command_table
    0,  // gcflag
};

/***************************************************************************
 *              Public access
 ***************************************************************************/
PUBLIC GCLASS *gclass_dba_postgres(void)
{
    return &_gclass;
}

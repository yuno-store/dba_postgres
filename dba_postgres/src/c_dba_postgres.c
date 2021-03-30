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
PRIVATE json_t *cmd_help(hgobj gobj, const char *cmd, json_t *kw, hgobj src);

PRIVATE sdata_desc_t pm_help[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "cmd",          0,              0,          "command about you want help."),
SDATAPM (ASN_UNSIGNED,  "level",        0,              0,          "command search level in childs"),
SDATA_END()
};

PRIVATE const char *a_help[] = {"h", "?", 0};

PRIVATE sdata_desc_t command_table[] = {
/*-CMD---type-----------name----------------alias-------items-------json_fn---------description--*/
SDATACM (ASN_SCHEMA,    "help",             a_help,     pm_help,    cmd_help,       "Command's help"),
SDATA_END()
};


/*---------------------------------------------*
 *      Attributes - order affect to oid's
 *---------------------------------------------*/
PRIVATE sdata_desc_t tattr_desc[] = {
/*-ATTR-type------------name------------flag--------------------default-----description--*/
SDATADF (ASN_OCTET_STR, "url",          SDF_PERSIST|SDF_WR,     0,          "Url",          30,     "Connection url."),
SDATADF (ASN_BOOLEAN,   "opened",       SDF_RD,                 0,          "Opened",       10,     "Channel opened."),
SDATA (ASN_COUNTER64,   "txMsgs",       SDF_RD|SDF_RSTATS,      0,          "Messages transmitted"),
SDATA (ASN_COUNTER64,   "rxMsgs",       SDF_RD|SDF_RSTATS,      0,          "Messages receiveds"),

SDATA (ASN_COUNTER64,   "txMsgsec",     SDF_RD|SDF_RSTATS,      0,          "Messages by second"),
SDATA (ASN_COUNTER64,   "rxMsgsec",     SDF_RD|SDF_RSTATS,      0,          "Messages by second"),
SDATA (ASN_COUNTER64,   "maxtxMsgsec",  SDF_WR|SDF_RSTATS,      0,          "Max Tx Messages by second"),
SDATA (ASN_COUNTER64,   "maxrxMsgsec",  SDF_WR|SDF_RSTATS,      0,          "Max Rx Messages by second"),

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
 *              Private data
 *---------------------------------------------*/
typedef struct _PRIVATE_DATA {
    int32_t timeout;
    hgobj timer;

    hgobj gobj_input_side;

    hgobj gobj_postgres;

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

    priv->timer = gobj_create(gobj_name(gobj), GCLASS_TIMER, 0, gobj);
    priv->ptxMsgs = gobj_danger_attr_ptr(gobj, "txMsgs");
    priv->prxMsgs = gobj_danger_attr_ptr(gobj, "rxMsgs");

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
     *  Start services
     */
    priv->gobj_input_side = gobj_find_service("__input_side__", TRUE);
    gobj_subscribe_event(priv->gobj_input_side, 0, 0, gobj);
    gobj_start_tree(priv->gobj_input_side);

    priv->gobj_postgres = gobj_find_service("__postgres__", TRUE);
    gobj_subscribe_event(priv->gobj_postgres, 0, 0, gobj);
    gobj_start_tree(priv->gobj_postgres);

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
    gobj_unsubscribe_event(priv->gobj_input_side, 0, 0, gobj);
    EXEC_AND_RESET(gobj_stop_tree, priv->gobj_input_side);

    gobj_unsubscribe_event(priv->gobj_postgres, 0, 0, gobj);
    EXEC_AND_RESET(gobj_stop_tree, priv->gobj_postgres);

    clear_timeout(priv->timer);

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
// PRIVATE json_t *record2insertsql(
//     hgobj gobj,
//     const char *table,
//     json_t *msg // owned
// )
// {
//     PRIVATE_DATA *priv = gobj_priv_data(gobj);
//
//     GBUFFER *gbuf = gbuf_create(1*1024, 1*1024, 0, 0);
//
//     gbuf_printf(gbuf, "INSERT INTO %s (", table);
//
//     int idx = 0;
//     const char *key; json_t *value;
//     json_object_foreach(msg, key, value) {
//         if(idx > 0) {
//             gbuf_append_char(gbuf, ',');
//         }
//         if(strcmp(key, "__md_tranger__")==0) {
//             gbuf_printf(gbuf, "%s", "rowid");
//         } else {
//             gbuf_printf(gbuf, "%s", key);
//         }
//         idx++;
//     }
//
//     gbuf_printf(gbuf, ") VALUES (");
//
//     idx = 0;
//     json_object_foreach(msg, key, value) {
//         if(idx > 0) {
//             gbuf_append_char(gbuf, ',');
//         }
//
//         if(strcmp(key, "__md_tranger__")==0) {
//             gbuf_printf(gbuf, "%"JSON_INTEGER_FORMAT, kw_get_int(value, "__rowid__", 0, KW_REQUIRED));
//         } else {
//             char *s = json2uglystr(value);
//             // TODO IMPORTANTE char *ss = PQescapeLiteral(priv->conn, const char *str, size_t length);
//
//             change_char(s, '"', '\'');
//
//             if(strcmp(key, "tm")==0) {
//                 char temp[256];
//                 snprintf(temp, sizeof(temp),
//                     "('epoch'::timestamptz + %s * '1 second'::interval)", s
//                 );
//                 gbmem_free(s);
//
//                 s = gbmem_strdup(temp);
//             }
//
//             gbuf_append_string(gbuf, s);
//             gbmem_free(s);
//         }
//
//         idx++;
//     }
//
//     gbuf_printf(gbuf, ");");
//     char *p = gbuf_cur_rd_pointer(gbuf);
//     json_t *jn_query = json_string(p);
//     gbuf_decref(gbuf);
//
//     JSON_DECREF(msg);
//     return jn_query;
// }

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int process_msg(
    hgobj gobj,
    json_t *kw,  // NOT owned
    hgobj src
)
{
//     json_t *query;
//     query = json_pack("{s:o}",
//         "query",
//         record2insertsql(gobj, "tracks_geodb2", msg)
//     );
//     print_json(query); // TODO TEST
//
//     gobj_send_event(priv->gobj_postgres, "EV_SEND_QUERY", query, gobj);
//
//     query = json_pack("{s:s}",
//         "query", "SELECT * from tracks_geodb2;"
//     );
//
//     gobj_send_event(priv->gobj_postgres, "EV_SEND_QUERY", query, gobj);


    return -1;
}




            /***************************
             *      Actions
             ***************************/




/***************************************************************************
 *  Connection from
 *      Input gates (__input_side__)
 ***************************************************************************/
PRIVATE int ac_on_open(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(src == priv->gobj_input_side) {

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
 *  Disconnection from
 *      Input gates (__input_side__)
 ***************************************************************************/
PRIVATE int ac_on_close(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(src == priv->gobj_input_side) {

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
//     {"EV_LIST_TRACKS",      EVF_PUBLIC_EVENT,  0,  0},

    {"EV_ON_OPEN",          0,  0,  0},
    {"EV_ON_CLOSE",         0,  0,  0},
    // bottom input
    {"EV_TIMEOUT",          0,  0,  0},
    {"EV_STOPPED",          0,  0,  0},
    // internal
    {NULL, 0, 0, ""}
};
PRIVATE const EVENT output_events[] = {
    {NULL, 0, 0, ""}
};
PRIVATE const char *state_names[] = {
    "ST_IDLE",
    NULL
};

PRIVATE EV_ACTION ST_IDLE[] = {
    {"EV_ON_MESSAGE",       ac_on_message,      0},
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
        0, //mt_subscription_added,
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
    0,  // acl
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

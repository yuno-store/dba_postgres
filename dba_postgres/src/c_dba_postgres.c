/***********************************************************************
 *          C_DBA_POSTGRES.C
 *          Dba_postgres GClass.
 *
 *          DBA Dba_postgres
 *
 *          Copyright (c) 2021 by Niyamaka.
 *          All Rights Reserved.
 ***********************************************************************/
#include <grp.h>
#include <unistd.h>
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
PRIVATE json_t *record2createtable(
    hgobj gobj,
    const char *table,
    json_t *msg // owned
);
PRIVATE json_t *record2insertsql(
    hgobj gobj,
    const char *table,
    json_t *msg // owned
);

PRIVATE int send_ack(
    hgobj gobj,
    json_t *kw_ack,  // owned
    json_t *__temp__ // channel info
);

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
SDATA (ASN_OCTET_STR,   "__username__", SDF_RD,                 "",         "Username"),
SDATA (ASN_OCTET_STR,   "filename_mask",SDF_RD|SDF_REQUIRED,    "%Y-%m",        "System organization of tables (file name format, see strftime())"),
SDATA (ASN_BOOLEAN,     "master",       SDF_RD,                 TRUE,       "the master is the only that can write"),
SDATA (ASN_INTEGER,     "xpermission",  SDF_RD,                 02770,      "Use in creation, default 02770"),
SDATA (ASN_INTEGER,     "rpermission",  SDF_RD,                 0660,       "Use in creation, default 0660"),
SDATA (ASN_INTEGER,     "exit_on_error",0,                      LOG_OPT_EXIT_ZERO,"exit on error"),
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

    hgobj gobj_tranger_tasks;
    json_t *tranger_tasks_;
    int32_t exit_on_error;

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

    /*
     *  Do copy of heavy used parameters, for quick access.
     *  HACK The writable attributes must be repeated in mt_writing method.
     */
    SET_PRIV(timeout,               gobj_read_int32_attr)
    SET_PRIV(exit_on_error,             gobj_read_int32_attr)

    priv->timer = gobj_create(gobj_name(gobj), GCLASS_TIMER, 0, gobj);
    priv->ptxMsgs = gobj_danger_attr_ptr(gobj, "txMsgs");
    priv->prxMsgs = gobj_danger_attr_ptr(gobj, "rxMsgs");

    /*----------------------------------------*
     *  Check AUTHZS
     *----------------------------------------*/
    BOOL is_yuneta = FALSE;
    struct passwd *pw = getpwuid(getuid());
    if(strcmp(pw->pw_name, "yuneta")==0) {
        gobj_write_str_attr(gobj, "__username__", "yuneta");
        is_yuneta = TRUE;
    } else {
        static gid_t groups[30]; // HACK to use outside
        int ngroups = sizeof(groups)/sizeof(groups[0]);

        getgrouplist(pw->pw_name, 0, groups, &ngroups);
        for(int i=0; i<ngroups; i++) {
            struct group *gr = getgrgid(groups[i]);
            if(strcmp(gr->gr_name, "yuneta")==0) {
                gobj_write_str_attr(gobj, "__username__", "yuneta");
                is_yuneta = TRUE;
                break;
            }
        }
    }
    if(!is_yuneta) {
        trace_msg("User or group 'yuneta' is needed to run %s", gobj_yuno_role());
        printf("User or group 'yuneta' is needed to run %s\n", gobj_yuno_role());
        exit(0);
    }

    /*----------------------------*
     *  Create Tasks Timeranger
     *----------------------------*/
    const char *filename_mask = gobj_read_str_attr(gobj, "filename_mask");
    BOOL master = gobj_read_bool_attr(gobj, "master");
    int exit_on_error = gobj_read_int32_attr(gobj, "exit_on_error");
    int xpermission = gobj_read_int32_attr(gobj, "xpermission");
    int rpermission = gobj_read_int32_attr(gobj, "rpermission");

    char path[PATH_MAX];
    yuneta_realm_store_dir(
        path,
        sizeof(path),
        gobj_yuno_role(),
        gobj_yuno_realm_owner(),
        gobj_yuno_realm_id(),
        "tasks",
        TRUE
    );

    json_t *kw_tranger = json_pack("{s:s, s:s, s:b, s:i, s:i, s:i}",
        "path", path,
        "filename_mask", filename_mask,
        "master", master,
        "on_critical_error", exit_on_error,
        "xpermission", xpermission,
        "rpermission", rpermission
    );
    priv->gobj_tranger_tasks = gobj_create_service(
        "tranger_tasks",
        GCLASS_TRANGER,
        kw_tranger,
        gobj
    );
    priv->tranger_tasks_ = gobj_read_pointer_attr(priv->gobj_tranger_tasks, "tranger");
    if(!priv->tranger_tasks_) {
        log_critical(priv->exit_on_error,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_PARAMETER_ERROR,
            "msg",          "%s", "tranger NULL",
            NULL
        );
    }
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
    // Don't subscribe, will do the tasks
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
             *      Jobs
             ***************************/




/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *action_create_table_if_not_exists(
    hgobj gobj,
    const char *lmethod,
    json_t *kw,
    hgobj src
)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    json_t *input_data = gobj_read_json_attr(src, "input_data");
    json_t *_dba_postgres = kw_get_dict(input_data, "_dba_postgres", 0, KW_REQUIRED);

    json_t *query = json_pack("{s:o}",
        "query",
        record2createtable(
            gobj,
            "tracks_geodb2",
            _dba_postgres
        )
    );
    gobj_send_event(priv->gobj_postgres, "EV_SEND_QUERY", query, gobj);

    KW_DECREF(kw);
    return 0; // continue
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *result_create_table_if_not_exists(
    hgobj gobj,
    const char *lmethod,
    json_t *kw,
    hgobj src
)
{
    int result = kw_get_int(kw, "result", -1, KW_REQUIRED);
    KW_DECREF(kw);
    return (void *)(size_t)result;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *action_add_row(
    hgobj gobj,
    const char *lmethod,
    json_t *kw,
    hgobj src
)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    json_t *input_data = gobj_read_json_attr(src, "input_data");

//     json_t *query = json_pack("{s:o}",
//         "query",
//         record2insertsql(
//             gobj,
//             "tracks_geodb2",
//             input_data
//         )
//     );
//     gobj_send_event(priv->gobj_postgres, "EV_SEND_QUERY", query, gobj);

// TODO
json_t *_dba_postgres = kw_get_dict(input_data, "_dba_postgres", 0, KW_REQUIRED);
json_t *query = json_pack("{s:o}",
    "query",
    record2createtable(
        gobj,
        "tracks_geodb2",
        _dba_postgres
    )
);
gobj_send_event(priv->gobj_postgres, "EV_SEND_QUERY", query, gobj);

    KW_DECREF(kw);
    return (void *)0; // continue
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *result_add_row(
    hgobj gobj,
    const char *lmethod,
    json_t *kw,
    hgobj src
)
{
    json_t *jn_msg = kw;

    int result = kw_get_int(kw, "result", -1, KW_REQUIRED);
    if(result == 0) {
        json_t *__temp__ = kw_get_dict_value(jn_msg, "__temp__", 0, KW_REQUIRED|KW_EXTRACT);

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

    KW_DECREF(kw);
    return (void *)(size_t)result;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *action_list_rows(
    hgobj gobj,
    const char *lmethod,
    json_t *kw,
    hgobj src
)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

//     query = json_pack("{s:s}",
//         "query", "SELECT * from tracks_geodb2;"
//     );
//     gobj_send_event(priv->gobj_postgres, "EV_SEND_QUERY", query, gobj);

    KW_DECREF(kw);
    return (void *)0; // continue
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *result_list_rows(
    hgobj gobj,
    const char *lmethod,
    json_t *kw,
    hgobj src
)
{

    KW_DECREF(kw);
    return (void *)0; // continue
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
PRIVATE json_t *record2createtable(
    hgobj gobj,
    const char *table,
    json_t *msg // not owned
)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    GBUFFER *gbuf = gbuf_create(1*1024, 1*1024, 0, 0);

    gbuf_printf(gbuf,
        "CREATE TABLE IF NOT EXISTS tracks_geodb2 ("
            "rowid       bigint PRIMARY KEY,"
            "id          text,"
            "name        text,"
            "event       text,"
            "tm          timestamp,"
            "priority    bigint,"
            "gps_fixed   boolean,"
            "accuracy    bigint,"
            "speed       bigint,"
            "battery     bigint,"
            "altitude    bigint,"
            "heading     bigint,"
            "longitude   real,"
            "latitude    real"
        ");"
    );

    char *p = gbuf_cur_rd_pointer(gbuf);
    json_t *jn_query = json_string(p);

    gbuf_decref(gbuf);

    return jn_query;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *record2insertsql(
    hgobj gobj,
    const char *table,
    json_t *msg // not owned
)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    GBUFFER *gbuf = gbuf_create(4*1024, 4*1024, 0, 0);

    gbuf_printf(gbuf, "INSERT INTO %s (", table);

    int idx = 0;
    const char *key; json_t *value;
    json_object_foreach(msg, key, value) {
        if(idx > 0) {
            gbuf_append_char(gbuf, ',');
        }
        if(strcmp(key, "__md_tranger__")==0) {
            gbuf_printf(gbuf, "%s", "rowid");
        } else {
            gbuf_printf(gbuf, "%s", key);
        }
        idx++;
    }

    gbuf_printf(gbuf, ") VALUES (");

    idx = 0;
    json_object_foreach(msg, key, value) {
        if(idx > 0) {
            gbuf_append_char(gbuf, ',');
        }

        if(strcmp(key, "__md_tranger__")==0) {
            gbuf_printf(gbuf, "%"JSON_INTEGER_FORMAT, kw_get_int(value, "__rowid__", 0, KW_REQUIRED));
        } else {
            char *s = json2uglystr(value);
            // TODO IMPORTANTE char *ss = PQescapeLiteral(priv->conn, const char *str, size_t length);

            change_char(s, '"', '\'');

            if(strcmp(key, "tm")==0) {
                char temp[256];
                snprintf(temp, sizeof(temp),
                    "('epoch'::timestamptz + %s * '1 second'::interval)", s
                );
                gbmem_free(s);

                s = gbmem_strdup(temp);
            }

            gbuf_append_string(gbuf, s);
            gbmem_free(s);
        }

        idx++;
    }

    gbuf_printf(gbuf, ");");
    char *p = gbuf_cur_rd_pointer(gbuf);
    json_t *jn_query = json_string(p);

    gbuf_decref(gbuf);

    return jn_query;
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

    /*-----------------------------*
     *      Build task name
     *-----------------------------*/
    const char *id = kw_get_str(kw, "id", "", KW_REQUIRED);
    json_int_t __msg_key__ = kw_get_int(kw, "__md_trq__`__msg_key__", 0, KW_REQUIRED);
    if(!__msg_key__) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "Not __msg_key__, free queue's msg",
            "src",          "%s", gobj_full_name(src),
            NULL
        );
        return 0; // free the queue's msg
    }

    char task_name[NAME_MAX];
    snprintf(task_name, sizeof(task_name), "task-%s-%"JSON_INTEGER_FORMAT, id, __msg_key__);

    /*-----------------------------*
     *      Check if exists task
     *-----------------------------*/
    if(gobj_find_unique_gobj(task_name, FALSE)) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "task already active",
            "task_name",    "%s", task_name,
            NULL
        );
        return -1; // Don't send ack
    }

    /*-----------------------------*
     *      Create the task
     *-----------------------------*/
    json_t *kw_task = json_pack(
        "{s:I, s:I, s:O, s:["
            "{s:s, s:s},"
            "{s:s, s:s},"
            "{s:s, s:s}"
            "]}",
        "gobj_jobs", (json_int_t)(size_t)gobj,
        "gobj_results", (json_int_t)(size_t)priv->gobj_postgres,
        "input_data", kw,
        "jobs",
            "exec_action", "action_create_table_if_not_exists",
            "exec_result", "result_create_table_if_not_exists",
            "exec_action", "action_add_row",
            "exec_result", "result_add_row",
            "exec_action", "action_list_rows",
            "exec_result", "result_list_rows"
    );

    hgobj gobj_task = gobj_create_unique(task_name, GCLASS_TASK, kw_task, gobj);
    gobj_subscribe_event(gobj_task, "EV_END_TASK", 0, gobj);
    gobj_set_volatil(gobj_task, TRUE); // auto-destroy

    /*-----------------------*
     *      Start task
     *-----------------------*/
    gobj_start(gobj_task);

    return -1; // Don't send ack
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
PRIVATE int ac_end_task(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    int result = kw_get_int(kw, "result", -1, KW_REQUIRED);

    if(result < 0) {
    }

    KW_DECREF(kw);
    return 0;
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
    {"EV_END_TASK",         0,  0,  0},
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
    {"EV_END_TASK",         ac_end_task,        0},
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
    {"action_add_row",                      action_add_row, 0},
    {"result_add_row",                      result_add_row, 0},
    {"action_create_table_if_not_exists",   action_create_table_if_not_exists, 0},
    {"result_create_table_if_not_exists",   result_create_table_if_not_exists, 0},
    {"action_list_rows",                    action_list_rows, 0},
    {"result_list_rows",                    result_list_rows, 0},
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

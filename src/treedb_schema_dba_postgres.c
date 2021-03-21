#pragma once

/* ◀▲▼▶

    ()  string hook (1 unique childs)
    {}  dict hook   (N unique childs)
    []  list hook   (n not-unique childs)
    (↖) 1 fkey      (1 parent)
    [↖] n fkeys     (n parents)
    {↖} N fkeys     (N parents) ???


    * field required
    = field inherited

                        groups
            ┌───────────────────────────┐
            │* id                       │
            │                           │
            │                groups {}  │ ◀─┐N
            │                           │   │
            │            group_top (↖)  │ ──┘ 1
            │                           │
            │  description              │
            │  icon                     │
            │  properties               │
            │  disabled                 │
            │                           │
            │                devices {} │ ◀─┐N
            │                           │   │
            │                           │   │
            │  _geometry                │   │
            └───────────────────────────┘   │
                                            │
                                            │
                                            │
                        devices             │
            ┌───────────────────────────┐   │
            │* id                       │   │
            │                           │   │
            │                groups [↖] │ ──┘n
            │                           │
            │  name                     │
            │  description              │
            │  time                     │
            │  enabled                  │
            │  properties               │
            │  yuno                     │
            │                           │
            │                           │
            │  _geometry                │
            └───────────────────────────┘



*/

static char treedb_schema_dba_postgres[]= "\
{                                                                   \n\
    'id': 'treedb_dba_postgres',                                    \n\
    'schema_version': '1',                                          \n\
    'topics': [                                                     \n\
        {                                                           \n\
            'topic_name': 'groups',                                 \n\
            'pkey': 'id',                                           \n\
            'system_flag': 'sf_string_key',                         \n\
            'topic_version': '1',                                   \n\
            'cols': {                                               \n\
                'id': {                                             \n\
                    'header': 'Group',                              \n\
                    'type': 'string',                               \n\
                    'fillspace': 10,                                \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'groups': {                                         \n\
                    'header': 'Groups',                             \n\
                    'type': 'object',                               \n\
                    'fillspace': 10,                                \n\
                    'flag': [                                       \n\
                        'hook'                                      \n\
                    ],                                              \n\
                    'hook': {                                       \n\
                        'groups': 'group_top'                       \n\
                    }                                               \n\
                },                                                  \n\
                'group_top': {                                      \n\
                    'header': 'Top Group',                          \n\
                    'type': 'string',                               \n\
                    'fillspace': 10,                                \n\
                    'flag': [                                       \n\
                        'fkey'                                      \n\
                    ]                                               \n\
                },                                                  \n\
                'description': {                                    \n\
                    'header': 'Description',                        \n\
                    'fillspace': 10,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'writable',                                 \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'icon': {                                           \n\
                    'header': 'Icon',                               \n\
                    'fillspace': 10,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'writable',                                 \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'properties': {                                     \n\
                    'header': 'Properties',                         \n\
                    'fillspace': 10,                                \n\
                    'type': 'blob',                                 \n\
                    'flag': [                                       \n\
                        'writable',                                 \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'disabled': {                                       \n\
                    'header': 'disabled',                           \n\
                    'fillspace': 8,                                 \n\
                    'type': 'boolean',                              \n\
                    'flag': [                                       \n\
                        'writable',                                 \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'devices': {                                        \n\
                    'header': 'Devices',                            \n\
                    'type': 'object',                               \n\
                    'fillspace': 10,                                \n\
                    'flag': ['hook'],                               \n\
                    'hook': {                                       \n\
                        'devices': 'groups'                         \n\
                    }                                               \n\
                },                                                  \n\
                '_geometry': {                                      \n\
                    'header': 'Geometry',                           \n\
                    'type': 'blob',                                 \n\
                    'fillspace': 10,                                \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                }                                                   \n\
            }                                                       \n\
        },                                                          \n\
                                                                    \n\
        {                                                           \n\
            'topic_name': 'devices',                                \n\
            'pkey': 'id',                                           \n\
            'system_flag': 'sf_string_key',                         \n\
            'topic_version': '1',                                   \n\
            'cols': {                                               \n\
                'id': {                                             \n\
                    'header': 'Device',                             \n\
                    'type': 'string',                               \n\
                    'fillspace': 10,                                \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'groups': {                                         \n\
                    'header': 'Groups',                             \n\
                    'type': 'array',                                \n\
                    'fillspace': 10,                                \n\
                    'flag': [                                       \n\
                        'fkey'                                      \n\
                    ]                                               \n\
                },                                                  \n\
                'name': {                                           \n\
                    'header': 'Name',                               \n\
                    'type': 'string',                               \n\
                    'fillspace': 10,                                \n\
                    'flag': [                                       \n\
                        'writable',                                 \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'description': {                                    \n\
                    'header': 'Description',                        \n\
                    'type': 'string',                               \n\
                    'fillspace': 10,                                \n\
                    'flag': [                                       \n\
                        'writable',                                 \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'time': {                                           \n\
                    'header': 'Time',                               \n\
                    'type': 'integer',                              \n\
                    'fillspace': 10,                                \n\
                    'flag': [                                       \n\
                        'time',                                     \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'enabled': {                                        \n\
                    'header': 'Enabled',                            \n\
                    'fillspace': 8,                                 \n\
                    'type': 'boolean',                              \n\
                    'flag': [                                       \n\
                        'writable',                                 \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'properties': {                                     \n\
                    'header': 'Properties',                         \n\
                    'fillspace': 10,                                \n\
                    'type': 'dict',                                 \n\
                    'flag': [                                       \n\
                        'writable',                                 \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'yuno': {                                           \n\
                    'header': 'Yuno',                               \n\
                    'type': 'string',                               \n\
                    'fillspace': 10,                                \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                '_geometry': {                                      \n\
                    'header': 'Geometry',                           \n\
                    'type': 'dict',                                 \n\
                    'fillspace': 10,                                \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                }                                                   \n\
            }                                                       \n\
        }                                                           \n\
                                                                    \n\
    ]                                                               \n\
}                                                                   \n\
";

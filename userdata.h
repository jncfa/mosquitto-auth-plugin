#ifndef __USERDATA_H__
#define __USERDATA_H__

#include <stdio.h>
#include <string.h>

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "mqtt_protocol.h"

#include <openssl/ssl.h>
#include "utils.h"
#include "libpq-fe.h"

typedef struct auth_plugin_userdata { // data to store for the duration of the plugin
    PGconn * dbconn; // connection to database
    mosquitto_plugin_id_t * identifier; // identifier for setting up callbacks
    char* baseACLQuery; // base ACL query
    char* unixSocketPath; // path to unix socket (to validate unix socket connections)
} auth_plugin_userdata;

#endif//__USERDATA_H__
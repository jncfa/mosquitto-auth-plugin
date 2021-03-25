#ifndef __USERDATA_H__
#define __USERDATA_H__

#include <stdio.h>
#include <string.h>

#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "mqtt_protocol.h"

#include "libpq-fe.h"

typedef struct auth_plugin_userdata { // data to store for the duration of the plugin
    PGconn * dbconn; // connection to database
    mosquitto_plugin_id_t * identifier;
} auth_plugin_userdata;


enum ACL_ACCESS_TYPE{
    READ=1,
    WRITE=2,
    SUBSCRIBE=4
};
#endif//__USERDATA_H__
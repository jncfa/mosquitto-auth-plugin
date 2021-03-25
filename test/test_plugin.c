#include "userdata.h"

static int mosq_callback1(int event, void *event_data, void *userdata)
{
	mosquitto_log_printf(MOSQ_LOG_ERR, "auth1");
	return MOSQ_ERR_SUCCESS;
}

static int mosq_callback2(int event, void *event_data, void *userdata)
{
	mosquitto_log_printf(MOSQ_LOG_ERR, "auth2");
	return MOSQ_ERR_SUCCESS;
}

static int mosq_callback3(int event, void *event_data, void *userdata)
{
	mosquitto_log_printf(MOSQ_LOG_ERR, "auth3");
	return MOSQ_ERR_SUCCESS;
}

static int mosq_callback4(int event, void *event_data, void *userdata)
{
	mosquitto_log_printf(MOSQ_LOG_ERR, "auth4");
	return MOSQ_ERR_SUCCESS;
}

static int mosq_callback5(int event, void *event_data, void *userdata)
{
	mosquitto_log_printf(MOSQ_LOG_ERR, "auth5");
	return MOSQ_ERR_SUCCESS;
}

static int mosq_callback6(int event, void *event_data, void *userdata)
{
	mosquitto_log_printf(MOSQ_LOG_ERR, "auth6");
	return MOSQ_ERR_SUCCESS;
}


static int mosq_callback7(int event, void *event_data, void *userdata)
{
	mosquitto_log_printf(MOSQ_LOG_ERR, "auth7");
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **userdata, struct mosquitto_opt *options, int option_count)
{

	mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) Hello woarld.");
	auth_plugin_userdata* data = *userdata = 
	(auth_plugin_userdata*) mosquitto_calloc(1, sizeof(struct auth_plugin_userdata));

	data->identifier = identifier;
	const char * conninfo = "host=localhost port=5433 dbname=testdb user=dbuser password=dbpass";

	data->dbconn = PQconnectdb(conninfo);

	if (data == NULL){
		mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) Error allocating memory for user data.");
		return MOSQ_ERR_UNKNOWN;
	}

	int ret = mosquitto_callback_register(data->identifier, MOSQ_EVT_RELOAD, mosq_callback1, NULL, userdata);
	if (ret != MOSQ_ERR_SUCCESS) return ret;
	mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) %i", ret);


	mosquitto_callback_register(data->identifier, MOSQ_EVT_ACL_CHECK, mosq_callback2, NULL, userdata);
	if (ret != MOSQ_ERR_SUCCESS) return ret;
	mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) %i", ret);

	mosquitto_callback_register(data->identifier, MOSQ_EVT_BASIC_AUTH, mosq_callback3, NULL, userdata);
	if (ret != MOSQ_ERR_SUCCESS) return ret;
	mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) %i", ret);

	mosquitto_callback_register(data->identifier, MOSQ_EVT_EXT_AUTH_START, mosq_callback4, NULL, userdata);
	if (ret != MOSQ_ERR_SUCCESS) return ret;
	mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) %i", ret);

	mosquitto_callback_register(data->identifier, MOSQ_EVT_EXT_AUTH_CONTINUE, mosq_callback5, NULL, userdata);
	if (ret != MOSQ_ERR_SUCCESS) return ret;
	mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) %i", ret);

	mosquitto_callback_register(data->identifier, MOSQ_EVT_PSK_KEY, mosq_callback6, NULL, userdata);
	if (ret != MOSQ_ERR_SUCCESS) return ret;
	mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) %i", ret);

	mosquitto_callback_register(data->identifier, MOSQ_EVT_CONTROL, mosq_callback7, NULL, userdata);
	if (ret != MOSQ_ERR_SUCCESS) return ret;
	mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) %i", ret);

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_version(int supported_version_count, const int *supported_versions){
	return MOSQ_PLUGIN_VERSION;
}


int mosquitto_plugin_cleanup(void *userdata, struct mosquitto_opt *options, int option_count){
	mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) cleaning (%d)", userdata);

	auth_plugin_userdata* data = (auth_plugin_userdata*)(userdata);

	int ret = mosquitto_callback_unregister(data->identifier, MOSQ_EVT_RELOAD, mosq_callback1, NULL);
	if (ret != MOSQ_ERR_SUCCESS) return ret;
	mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) %i", ret);

	mosquitto_callback_unregister(data->identifier, MOSQ_EVT_ACL_CHECK, mosq_callback2, NULL);
	if (ret != MOSQ_ERR_SUCCESS) return ret;
	mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) %i", ret);

	mosquitto_callback_unregister(data->identifier, MOSQ_EVT_BASIC_AUTH, mosq_callback3, NULL);
	if (ret != MOSQ_ERR_SUCCESS) return ret;
	mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) %i", ret);

	mosquitto_callback_unregister(data->identifier, MOSQ_EVT_EXT_AUTH_START, mosq_callback4, NULL);
	if (ret != MOSQ_ERR_SUCCESS) return ret;
	mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) %i", ret);

	mosquitto_callback_unregister(data->identifier, MOSQ_EVT_EXT_AUTH_CONTINUE, mosq_callback5, NULL);
	if (ret != MOSQ_ERR_SUCCESS) return ret;
	mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) %i", ret);

	mosquitto_callback_unregister(data->identifier, MOSQ_EVT_PSK_KEY, mosq_callback6, NULL);
	if (ret != MOSQ_ERR_SUCCESS) return ret;	
	mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) %i", ret);

	mosquitto_callback_unregister(data->identifier, MOSQ_EVT_CONTROL, mosq_callback7, NULL);
	if (ret != MOSQ_ERR_SUCCESS) return ret;
	mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) %i", ret);


	PQfinish(data->dbconn);
	mosquitto_free(data);
	return MOSQ_ERR_SUCCESS;
}


#include "userdata.h"


/*
 * Search through `in' for tokens %c (clientid) and %u (username); build a
 * new malloc'd string at `res' with those tokens interpolated into it.
 */

void t_expand(const char *clientid, const char *username, const char *in, char **res)
{
	const char *s;
	char *work, *wp;
	int c_specials = 0, u_specials = 0, len;
	const char *ct, *ut;

	ct = (clientid) ? clientid : "";
	ut = (username) ? username : "";

	for (s = in; s && *s; s++) {
		if (*s == '%' && (*(s + 1) == 'c'))
			c_specials++;
		if (*s == '%' && (*(s + 1) == 'u'))
			u_specials++;
	}
	len = strlen(in) + 1;
	len += strlen(clientid) * c_specials;
	len += strlen(username) * u_specials;

	if ((work = mosquitto_malloc(len)) == NULL) {
		*res = NULL;
		return;
	}
	for (s = in, wp = work; s && *s; s++) {
		*wp++ = *s;
		if (*s == '%' && (*(s + 1) == 'c')) {
			*--wp = 0;
			strcpy(wp, ct);
			wp += strlen(ct);
			s++;
		}
		if (*s == '%' && (*(s + 1) == 'u')) {
			*--wp = 0;
			strcpy(wp, ut);
			wp += strlen(ut);
			s++;
		}
	}
	*wp = 0;

	*res = work;
}



/*
 * Function: mosquitto_auth_acl_check
 *
 * Called by the broker when topic access must be checked. access will be one
 * of:
 *  MOSQ_ACL_SUBSCRIBE when a client is asking to subscribe to a topic string.
 *                     This differs from MOSQ_ACL_READ in that it allows you to
 *                     deny access to topic strings rather than by pattern. For
 *                     example, you may use MOSQ_ACL_SUBSCRIBE to deny
 *                     subscriptions to '#', but allow all topics in
 *                     MOSQ_ACL_READ. This allows clients to subscribe to any
 *                     topic they want, but not discover what topics are in use
 *                     on the server.
 *  MOSQ_ACL_READ      when a message is about to be sent to a client (i.e. whether
 *                     it can read that topic or not).
 *  MOSQ_ACL_WRITE     when a message has been received from a client (i.e. whether
 *                     it can write to that topic or not).
 *
 * Return:
 *	MOSQ_ERR_SUCCESS if access was granted.
 *	MOSQ_ERR_ACL_DENIED if access was not granted.
 *	MOSQ_ERR_UNKNOWN for an application specific error.
 *	MOSQ_ERR_PLUGIN_DEFER if your plugin does not wish to handle this check.
 */
static int mosq_auth_acl_check(int event, void *event_data, void *userdata){
	bool match = false;

	struct mosquitto_evt_acl_check *ed = event_data;

	const char* username = mosquitto_client_username(ed->client), 
			*client_id = mosquitto_client_id(ed->client), 
			*topic = ed->topic;
	
	int access_type = ed->access;

	mosquitto_log_printf(MOSQ_LOG_ERR, "(mosq-auth) username{%s}, cid{%s}, topic{%s}, access{%d}", mosquitto_client_username(ed->client), mosquitto_client_id(ed->client), ed->topic, ed->access);

	struct auth_plugin_userdata* ud = *(auth_plugin_userdata**)userdata;

	const char* baseQuery = "SELECT topic_wildcard FROM mqtt_role_permissions INNER JOIN \
mqtt_clients USING(device_type) WHERE (device_id = '%s') AND (access_type & %d > 0)";

	char query[255];

	sprintf(query, baseQuery, client_id, access_type);

	mosquitto_log_printf(MOSQ_LOG_ERR, "test2");
	mosquitto_log_printf(MOSQ_LOG_ERR, "%s", query);

	PGresult *result = PQexec(ud->dbconn, query);
	mosquitto_log_printf(MOSQ_LOG_ERR, "test3");

	if (PQresultStatus(result) != PGRES_TUPLES_OK) {	
		mosquitto_log_printf(MOSQ_LOG_ERR, "(mosq-auth) db error: %s", PQresultErrorMessage(result));
	}

	if (PQnfields(result) != 1) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "(mosq-auth) numfields not ok : %d", PQnfields(result));
	}

	int rec_count = PQntuples(result);
	int row = 0;
	for (row = 0; row < rec_count; row++) {
		char * acl_wildcard = PQgetvalue(result, row, 0);

		if (acl_wildcard != NULL) {
			mosquitto_log_printf(MOSQ_LOG_ERR, "(mosq-auth) %s", acl_wildcard);

			char *expanded;

			t_expand(client_id, username, acl_wildcard, &expanded);
			if (expanded && *expanded) {
				bool result;
				mosquitto_topic_matches_sub(expanded, topic, &result);

				mosquitto_log_printf(MOSQ_LOG_ERR,  "  postgres: topic_matches(%s, %s) == %d",
				     expanded, topic, result);
				
				mosquitto_free(expanded);
				
				if (result){
					match = true;	
					break;	
				}
			}
		}
	}
	return match ? MOSQ_ERR_SUCCESS : MOSQ_ERR_ACL_DENIED;
}

/*
 * Function: mosquitto_plugin_init
 *
 * Called after the plugin has been loaded and <mosquitto_plugin_version>
 * has been called. This will only ever be called once and can be used to
 * initialise the plugin.
 *
 * Parameters:
 *
 *  identifier -     This is a pointer to an opaque structure which you must
 *                   save and use when registering/unregistering callbacks.
 *	user_data -      The pointer set here will be passed to the other plugin
 *	                 functions. Use to hold connection information for example.
 *	opts -           Pointer to an array of struct mosquitto_opt, which
 *	                 provides the plugin options defined in the configuration file.
 *	opt_count -      The number of elements in the opts array.
 *
 * Return value:
 *	Return 0 on success
 *	Return >0 on failure.
 */
int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **userdata, struct mosquitto_opt *options, int option_count)
{

	mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) Hello world.");
	auth_plugin_userdata* data = *userdata = 
	(auth_plugin_userdata*) mosquitto_calloc(1, sizeof(struct auth_plugin_userdata));


	if (data == NULL){
		mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) Error allocating memory for user data.");
		return MOSQ_ERR_UNKNOWN;
	}

	// set identifier	
	data->identifier = identifier;
	const char * conninfo = "host=localhost port=5433 dbname=testdb user=dbuser password=dbpass";
	
	/*

	char * dbname, dbuser, dbpass, dbport;
	
	// no
	for (int idx = 0; idx < option_count; idx++){
		char* key = options[idx].key, value = options[idx].value;
		
		if (!strcmp(key, "dbname")){

		}
		else if (!strcmp(key, "dbuser")){

		}
		else if (!strcmp(key, "dbpass")){

		}
	}
	
	data->dbconn = PQsetdbLogin(...);
		
	*/

	data->dbconn = PQconnectdb(conninfo);
	
	/* Check to see that the backend connection was successfully made */
    if (PQstatus(data->dbconn) != CONNECTION_OK)
    {
        fprintf(stderr, "Connection to database failed: %s",
                PQerrorMessage(data->dbconn));
        return MOSQ_ERR_UNKNOWN;
    }

	int ret = mosquitto_callback_register(data->identifier, MOSQ_EVT_ACL_CHECK, mosq_auth_acl_check, NULL, userdata);
	if (ret != MOSQ_ERR_SUCCESS) return ret;
	mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) %i", ret);

	return MOSQ_ERR_SUCCESS;
}
/*
 * Function: mosquitto_plugin_version
 *
 * The broker will attempt to call this function immediately after loading the
 * plugin to check it is a supported plugin version. Your code must simply
 * return the plugin interface version you support, i.e. 5.
 *
 * The supported_versions array tells you which plugin versions the broker supports.
 *
 * If the broker does not support the version that you require, return -1 to
 * indicate failure.
 */
int mosquitto_plugin_version(int supported_version_count, const int *supported_versions){
	return MOSQ_PLUGIN_VERSION;
}

/*
 * Function: mosquitto_plugin_cleanup
 *
 * Called when the broker is shutting down. This will only ever be called once
 * per plugin.
 *
 * Parameters:
 *
 *	user_data -      The pointer provided in <mosquitto_plugin_init>.
 *	opts -           Pointer to an array of struct mosquitto_opt, which
 *	                 provides the plugin options defined in the configuration file.
 *	opt_count -      The number of elements in the opts array.
 *
 * Return value:
 *	Return 0 on success
 *	Return >0 on failure.
 */
int mosquitto_plugin_cleanup(void *userdata, struct mosquitto_opt *options, int option_count){
	mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) cleaning");

	auth_plugin_userdata* data = (auth_plugin_userdata*)(userdata);

	int ret = mosquitto_callback_unregister(data->identifier, MOSQ_EVT_ACL_CHECK, mosq_auth_acl_check, NULL);
	if (ret != MOSQ_ERR_SUCCESS) return ret;
	mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) %i", ret);

	// close database connection
	PQfinish(data->dbconn);
	
	// free allocated data
	mosquitto_free(data);

	return MOSQ_ERR_SUCCESS;
}


#include "userdata.h"
//#define DEBUG

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
static int mosq_auth_acl_check(int event, void *event_data, void *userdata)
{
	bool match = false;
	struct mosquitto_evt_acl_check *ed = event_data;

	const char *username = mosquitto_client_username(ed->client),
			   *client_id = mosquitto_client_id(ed->client),
			   *topic = ed->topic;

	int access_type = ed->access;

#ifdef DEBUG
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "(mosquitto-auth-plugin) username{%s}, cid{%s}, topic{%s}, access{%d}", mosquitto_client_username(ed->client), mosquitto_client_id(ed->client), ed->topic, ed->access);
#endif

	// grab userdata passed to the function
	struct auth_plugin_userdata *ud = *(auth_plugin_userdata **)userdata;

	// build query string
	const char *baseQuery = ud->baseACLQuery;

	char *query = (char *)mosquitto_malloc(sizeof(char) * (strlen(baseQuery) + strlen(client_id) + 1));
	sprintf(query, baseQuery, client_id, access_type);

#ifdef DEBUG
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "%s", query);
#endif

	// query database for topics with the requested permission
	// and check for errors
	PGresult *result = PQexec(ud->dbconn, query);

	if (PQresultStatus(result) != PGRES_TUPLES_OK)
	{
		mosquitto_log_printf(MOSQ_LOG_DEBUG, "(mosquitto-auth-plugin) Database error: %s.", PQresultErrorMessage(result));
	}

	if (PQnfields(result) != 1)
	{
		mosquitto_log_printf(MOSQ_LOG_DEBUG, "(mosquitto-auth-plugin) Database error: Expected 1 number of fields, got %d.", PQnfields(result));
	}

	// get number of results to iterate
	int rec_count = PQntuples(result);
	for (int row = 0; row < rec_count; row++)
	{
		char *acl_wildcard = PQgetvalue(result, row, 0);

		if (acl_wildcard != NULL)
		{
#ifdef DEBUG
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "(mosquitto-auth-plugin) %s", acl_wildcard);
#endif
			char *expanded;

			t_expand(client_id, username, acl_wildcard, &expanded);
			if (expanded && *expanded)
			{
				bool result;
				//mosquitto_sub_matches(expanded, topic, &result);
				result = sub_acl_check(expanded, topic);
#ifdef DEBUG
				mosquitto_log_printf(MOSQ_LOG_DEBUG, "(mosquitto-auth-plugin) topic_matches(%s, %s) == %d",
									 expanded, topic, result);
#endif

				mosquitto_free(expanded);

				if (result)
				{
					match = true; // matches at least 1 topic with valid permissions, user is authorized
					break;
				}
			}
			else
			{
				mosquitto_free(expanded);
			}
		}
	}
	return match ? MOSQ_ERR_SUCCESS : MOSQ_ERR_ACL_DENIED;
}

/*
 * Function: mosq_basic_auth_check
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
static int mosq_basic_auth_check(int event, void *event_data, void *userdata)
{
#ifdef DEBUG
	mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) New client connected.");
#endif
	// get event data
	struct mosquitto_evt_basic_auth *ed = event_data;
	// grab userdata passed to the function
	struct auth_plugin_userdata *ud = *(auth_plugin_userdata **)userdata;

	// get client certificate and subject
	X509 *client_cert = mosquitto_client_certificate(ed->client);

	if (!strcmp(mosquitto_client_address(ed->client), ud->unixSocketPath)) { // Unix Socket communication (trusted)
	
		// get client id and username
		const char *client_id = mosquitto_client_id(ed->client);
		// get client id and username
		const char *client_username = mosquitto_client_username(ed->client);

		// for unix socket communication, the client MUST supply username and client id
		if (!client_username || !client_id){
			return MOSQ_ERR_AUTH;
		}
		// check if client id is in the certificate's common name / username (as in the specification)
		else if (!strstr(client_username, client_id))
		{
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "(mosquitto-auth-plugin) Mismatch between client id (%s) and username (%s), connection refused.", client_id, client_username);
			return MOSQ_ERR_AUTH;
		}
		else
		{
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "(mosquitto-auth-plugin) Found local client id (%s) in username (%s), connection allowed.", client_id, client_username);
			return MOSQ_ERR_SUCCESS;
		}
	}
	else if (client_cert){ // TLS IP communication
		X509_NAME *name = X509_get_subject_name(client_cert);

		// get index of the common name
		int commonName_idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
		if (commonName_idx == -1)
		{
			// free allocated data
			X509_free(client_cert);
			return MOSQ_ERR_UNKNOWN;
		}

		// get name entry of common name
		X509_NAME_ENTRY *commonNameEntry = X509_NAME_get_entry(name, commonName_idx);
		if (commonNameEntry)
		{
			// get value of common name
			ASN1_STRING *name_asn1 = X509_NAME_ENTRY_get_data(commonNameEntry);
			if (name_asn1 == NULL)
			{
				X509_free(client_cert);
				return MOSQ_ERR_UNKNOWN;
			}
			// get user name depending on OpenSSL version
	#if OPENSSL_VERSION_NUMBER < 0x10100000L
			char *username = (char *)ASN1_STRING_data(name_asn1);
	#else
			char *username = (char *)ASN1_STRING_get0_data(name_asn1);
	#endif

	#ifdef DEBUG
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "(mosquitto-auth-plugin) Got common name and seting as new username for client: %s", username);
	#endif
			// set client username
			int ret = mosquitto_set_username(ed->client, username);

	#ifdef DEBUG
			mosquitto_log_printf(MOSQ_LOG_DEBUG, "(mosquitto-auth-plugin) Setting username returned %u", ret);
	#endif
			// free allocated memory since it is not longer required
			X509_free(client_cert);

			// get client id and username
			const char *client_id = mosquitto_client_id(ed->client);

			// check if client id is in the certificate's common name / username (as in the specification)
			if (!strstr(username, client_id))
			{
				mosquitto_log_printf(MOSQ_LOG_DEBUG, "(mosquitto-auth-plugin) Mismatch between client id (%s) and username (%s), connection refused.", client_id, username);
				return MOSQ_ERR_AUTH;
			}
			else
			{
				mosquitto_log_printf(MOSQ_LOG_DEBUG, "(mosquitto-auth-plugin) Found client id (%s) in username (%s), connection allowed.", client_id, username);
				return MOSQ_ERR_SUCCESS;
			}
		}

		X509_free(client_cert);
		return MOSQ_ERR_UNKNOWN;
	}

	// unknown error
	return MOSQ_ERR_UNKNOWN;
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

	mosquitto_log_printf(MOSQ_LOG_INFO, "(mosquitto-auth-plugin) Starting auth plugin.");
	auth_plugin_userdata *data = *userdata =
		(auth_plugin_userdata *)mosquitto_calloc(1, sizeof(struct auth_plugin_userdata));

	if (data == NULL)
	{
		mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) Error allocating memory for user data.");
		return MOSQ_ERR_UNKNOWN;
	}

	// set identifier
	data->identifier = identifier;

	// setup connection via peer authentication, therefore no password is exchanged
	const char *baseConninfo = "dbname='%s' port=%s";

	char *dbname = NULL, *dbport = NULL;
	data->baseACLQuery = NULL;
	data->unixSocketPath = NULL;

	mosquitto_log_printf(MOSQ_LOG_DEBUG, "(mosquitto-auth-plugin) Parsing options, recieved %u options.", option_count);
	struct mosquitto_opt *option = options;
	for (int idx = 0; idx < option_count; idx++, option++)
	{
		mosquitto_log_printf(MOSQ_LOG_DEBUG, "(mosquitto-auth-plugin) Parsing option %u: (%s %s)", idx + 1, option->key, option->value);

		if (!strcmp(option->key, "db_name"))
		{
			dbname = option->value;
			// error allocating memory
			if (dbname == NULL)
			{
				return MOSQ_ERR_NOMEM;
			}
		}
		else if (!strcmp(option->key, "db_port"))
		{
			dbport = option->value;
			// error allocating memory
			if (dbport == NULL)
			{
				return MOSQ_ERR_NOMEM;
			}
		}
		else if (!strcmp(option->key, "db_aclquery"))
		{
			data->baseACLQuery = mosquitto_strdup(option->value);
			// error allocating memory
			if (data->baseACLQuery == NULL)
			{
				return MOSQ_ERR_NOMEM;
			}
		}
		else if (!strcmp(option->key, "unixsocket_path"))
		{
			data->unixSocketPath = mosquitto_strdup(option->value);
			// error allocating memory
			if (data->unixSocketPath == NULL)
			{
				return MOSQ_ERR_NOMEM;
			}
		}
	}
	// if name or port is not set then exit
	if (!(dbname && dbport && data->baseACLQuery && data->unixSocketPath))
	{
		mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) Couldn't retrieve all parameters from configuration file, make sure you are setting it properly! (%p %p %p %p)", dbname, dbport, data->baseACLQuery, data->unixSocketPath);
		return MOSQ_ERR_UNKNOWN;
	}

	// allocate connection string according to the size of each param and parse it
	char *conninfo = (char *)mosquitto_malloc(sizeof(char) * (strlen(dbname) + strlen(dbport) + strlen(baseConninfo)));
	sprintf(conninfo, baseConninfo, dbname, dbport);

	mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) Parsed conninfo: %s", conninfo);

	// establish connection to the database
	data->dbconn = PQconnectdb(conninfo);
	/* Check to see that the backend connection was successfully made */
	if (PQstatus(data->dbconn) != CONNECTION_OK)
	{
		mosquitto_log_printf(MOSQ_LOG_ERR, "(mosquitto-auth-plugin) Connection to database failed: %s",
							 PQerrorMessage(data->dbconn));

		mosquitto_free(conninfo);
		return MOSQ_ERR_UNKNOWN;
	}

	mosquitto_log_printf(MOSQ_LOG_INFO, "(mosquitto-auth-plugin) Successfully initialized connection to database.");

	// setting up callbacks for authentication
	int ret = mosquitto_callback_register(data->identifier, MOSQ_EVT_ACL_CHECK, mosq_auth_acl_check, NULL, userdata);
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "(mosquitto-auth-plugin) Registering ACL callback returned (%i)", ret);

	int ret2 = mosquitto_callback_register(data->identifier, MOSQ_EVT_BASIC_AUTH, mosq_basic_auth_check, NULL, userdata);
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "(mosquitto-auth-plugin) Registering AUTH callback returned (%i)", ret2);

	// free allocated memory as it isn't required anymore
	mosquitto_free(conninfo);

	return ret | ret2 ? MOSQ_ERR_UNKNOWN : MOSQ_ERR_SUCCESS;
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
int mosquitto_plugin_version(int supported_version_count, const int *supported_versions)
{
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
int mosquitto_plugin_cleanup(void *userdata, struct mosquitto_opt *options, int option_count)
{
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "(mosquitto-auth-plugin) Cleaning plugin data.");

	// grab userdata
	auth_plugin_userdata *data = (auth_plugin_userdata *)(userdata);

	// unregister ACL callback
	int ret = mosquitto_callback_unregister(data->identifier, MOSQ_EVT_ACL_CHECK, mosq_auth_acl_check, NULL);
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "(mosquitto-auth-plugin) Unregistering ACL callback returned (%i)", ret);
	int ret2 = mosquitto_callback_unregister(data->identifier, MOSQ_EVT_BASIC_AUTH, mosq_basic_auth_check, NULL);
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "(mosquitto-auth-plugin) Unregistering AUTH callback returned (%i)", ret2);

	// close and free database connection
	PQfinish(data->dbconn);

	// free allocated data
	mosquitto_free(data->unixSocketPath);
	mosquitto_free(data->baseACLQuery);
	mosquitto_free(data);

	return ret | ret2 ? MOSQ_ERR_UNKNOWN : MOSQ_ERR_SUCCESS;
}
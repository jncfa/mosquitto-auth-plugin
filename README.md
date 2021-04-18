# Mosquitto Auth Plugin

> Simple plugin used for establishing authentication and authorization for our MQTT broker.

This plugin subscribes to authentication and authorization events from the MQTT broker. 

It validates the MQTT clients' communications through queries to an PostgreSQL database containing the permissions for each client.

### Installing

This plugin does not require any additional packages besides those required by `mosquitto` itself. This plugin is also compiled automatically when building `mosquitto`.

If this plugin is not compiled automatically, make sure to configure CMake with `-DWITH_PLUGINS=ON` to force the plugin compilation.

## Contributing

Please use the [issue tracker](https://bitbucket.org/wow-project/mosquitto-auth-plugin/issues) for submmitting any issues, and use [pull requests](https://bitbucket.org/wow-project/mosquitto-auth-plugin/pull-requests/) to patch those issues!

### Version

#### Version 1.01

 - Added an additional authentication step, to refuse connection if the MQTT client's certificate CN does not contain the client ID (used for authorizing the client);
 - Changed database connection type from TCP to Unix Socket, using a different and simpler authentication method ([peer authentication](https://www.postgresql.org/docs/current/auth-peer.html));

#### Version 1.00

 - Initial commit with a simple authentication plugin (with hardcoded parameters).

find_package(PostgreSQL REQUIRED)
find_package(OpenSSL REQUIRED)

include_directories(${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/include
	${STDBOOL_H_PATH} ${STDINT_H_PATH} ${PTHREAD_INCLUDE_DIR} ${PostgreSQL_INCLUDE_DIRS}
	${OPENSSL_INCLUDE_DIR} ${mosquitto_SOURCE_DIR}/deps
	${mosquitto_SOURCE_DIR}/src)

link_directories(${mosquitto_BINARY_DIR}/lib ${mosquitto_SOURCE_DIR} ${PostgreSQL_LIBRARY_DIRS} ${OPENSSL_LIBRARY_DIR})

add_library(mosquitto_auth_plugin SHARED mosquitto_auth_plugin.c sub_matches_sub.c utils.c)

target_link_libraries(mosquitto_auth_plugin PRIVATE ${MOSQUITTO_LIBRARIES} ${PostgreSQL_LIBRARIES} ${OPENSSL_LIBRARIES})

set_target_properties(mosquitto_auth_plugin PROPERTIES
	POSITION_INDEPENDENT_CODE 1
)
set_target_properties(mosquitto_auth_plugin PROPERTIES PREFIX "")

install(TARGETS mosquitto_auth_plugin RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")

SET(CMAKE_LIBRARY_PATH "/usr/local/lib")
LINK_DIRECTORIES("/usr/local/lib")
include_directories ("/usr/local/include")
MYSQL_ADD_PLUGIN(ldap_authorization ldap_authorization.c
  MODULE_ONLY MODULE_OUTPUT_NAME "ldap_authorization"
  LINK_LIBRARIES "ldap")


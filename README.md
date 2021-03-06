ldap_authorization
==================

MySQL plugin for authorization user at LDAP

Installation:
- copy plugin dir in ${MYSQLSRCDIR}/plugin/;
- run `make' command in ${MYSQLSRCDIR};
- copy plugin ${MYSQLSRCDIR}/plugin/ldap_authorization.so to your mysql_plugin_dir (Perhaps, it is /usr/local/lib/mysql/plugin/);
- in mysql console run: 
    mysql> INSTALL PLUGIN ldap_authorization SONAME 'ldap_authorization.so';

Configuration option for plugin:
- ldap_authorization_host - like 'ldap://127.0.0.1,ldap://192.168.0.1' - is required field
- ldap_authorization_port - int - isn't required field
- ldap_authorization_validgroups - field for list of valid groups for current mysql node. Groups are separated by commas. This group must be using for 'CREATE user' statement - is required field
- ldap_authorization_binddn - login who can get access to LDAP catalog - is required field
- ldap_authorization_bindpasswd - password for login from ldap_authorization_binddn field - is required field
- ldap_authorization_defaultfilter - filter for limit search in LDAP catalog - isn't required field
- ldap_authorization_timeout - set timeout for get answer from LDAP - isn't required field
- ldap_authorization_tls - use TLS connection? - isn't required field. Valid values - 0 or 1. Default - 0.
- ldap_authorization_debug - print debug message - isn't required field. Valid values - 0 or 1. Default - 0.

Example config:


ldap_authorization_debug=ON

ldap_authorization_bindpasswd='mega_password_for_readonly'

ldap_authorization_binddn='cn=readonly,dc=example,dc=com'

ldap_authorization_basedn='dc=example,dc=com'

ldap_authorization_auth_host='ldap://192.168.0.1,ldap://192.168.0.2'

ldap_authorization_validgroups='ldap_group1,ldap_group2'


For add new user in MySQL server:
- mysql> DELETE FROM mysql.user where User='';
- mysql> FLUSH PRIVILEGES;
- mysql> CREATE USER ''@'192.168.0.%' IDENTIFIED WITH ldap_authorization as 'ldap_group1 ldap_group2'; /* BaseDN change to your date. ex. dc=example,dc=net */
- mysql> CREATE USER 'ldap_group1'@'192.168.0.%' identified by '123pass'; /* ldap_group1 must be set at ldap_authorization_validgroups variable */
- mysql> CREATE USER 'ldap_group2'@'192.168.0.%' identified by '321pass'; /* ldap_group2 must be set at ldap_authorization_validgroups variable */
Create proxy user for give permissions:
- mysql> GRANT PROXY ON 'ldap_group1'@'192.168.0.%' TO ''@'192.168.0.%';
- mysql> GRANT PROXY ON 'ldap_group2'@'192.168.0.%' TO ''@'192.168.0.%';

For check:
- SELECT USER(), CURRENT_USER(), @@proxy_user, @@external_user\G

Addition:
- All log messages is gone via syslog

#include <mysql/plugin_auth.h>
#include <mysql/client_plugin.h>
#include <my_global.h>
#include <mysql.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <ldap.h>

#define MAXLOGBUF	256
#define MAXLOGBUFEX	512
#define MAXFILTERSTR	128
#define MAXAUTHSTR	128
#define MINAUTHSTR	3
#define MAXCFGLINE	1024
#define MAXGROUPLIST	512	

#if !defined(__attribute__) && (defined(__cplusplus) || !defined(__GNUC__)  || __GNUC__ == 2 && __GNUC_MINOR__ < 8)
#define __attribute__(A)
#endif

static char *ldap_authorization_host = 0;	    /* 127.0.0.1 */
static unsigned int ldap_authorization_port = 0;   /* 3389 */
//static char *ldap_authorization_basedn = 0;	    /* dc=bsdway,dc=ru */
static char *ldap_authorization_validgroups = 0;    /* */
static char *ldap_authorization_binddn = 0;
static char *ldap_authorization_bindpasswd = 0;
static char *ldap_authorization_defaultfilter = 0;
static unsigned int ldap_authorization_timeout = 0;
static char ldap_authorization_tls = 0;
static char ldap_authorization_debug = 0;

static void
ldap_log(int priority, char *msg)
{
  char *env = NULL;	
  openlog("ldap_authorization", LOG_PID|LOG_CONS, LOG_USER);
  if (priority == LOG_DEBUG && ldap_authorization_debug)  	
  {
	  char logbuf[MAXLOGBUF];
	  memset(logbuf, 0, MAXLOGBUF);
	  snprintf(logbuf, MAXLOGBUF, "[DEBUG] ldap_authorization: %s", msg);
	  syslog(LOG_DEBUG, logbuf);
  } else
    syslog(LOG_INFO, msg);
  closelog();
};

static char*
get_full_user_path(char *user, const char* ldap_authorization_basedn) {
	LDAP *ldapsession;
	LDAPMessage *res, *entry;
	int rc, tls_version, count = 0;
	char filter[MAXFILTERSTR];
	char logbuf[MAXLOGBUF];
	char *dn;

	/* Init LDAP */
	if(ldap_initialize(&ldapsession, ldap_authorization_host))
	{
		ldap_log(LOG_ERR, "Ldap connection initialize return fail status");
		return NULL;
	}

	/* Start TLS if we need it*/
	if (ldap_authorization_tls) {
		tls_version = LDAP_VERSION3;
		ldap_set_option(ldapsession, LDAP_OPT_PROTOCOL_VERSION, &tls_version);
		if((rc = ldap_start_tls_s(ldapsession, NULL,NULL))!=LDAP_SUCCESS)
		{
		    snprintf(logbuf, MAXLOGBUF, "Ldap start TLS error: %s. ", ldap_err2string(rc));	
		    ldap_log(LOG_WARNING, logbuf);
		}
	}

	/* Check authorization */
#if LDAP_API_VERSION > 3003
	struct berval cred;
	struct berval *msgidp=NULL;
	cred.bv_val = ldap_authorization_bindpasswd;
	cred.bv_len = strlen(ldap_authorization_bindpasswd);
	if((rc = ldap_sasl_bind_s(ldapsession, ldap_authorization_binddn, "DIGEST-MD5", &cred, NULL, NULL, &msgidp))!=LDAP_SUCCESS) {
#else	
	if((rc = ldap_simple_bind_s(ldapsession, ldap_authorization_binddn, ldap_authorization_bindpasswd))!=LDAP_SUCCESS) {
#endif
		snprintf(logbuf, MAXLOGBUF, "Ldap server %s authentificate failed: %s", ldap_authorization_host, ldap_err2string(rc));	
		ldap_log(LOG_DEBUG, logbuf);
		return NULL;
	};

	/* create filter for search */
	memset(filter, 0, MAXFILTERSTR);
	snprintf(filter, MAXLOGBUF, "(uid=%s)", user);

	if ((rc = ldap_search_ext_s(ldapsession, ldap_authorization_basedn, LDAP_SCOPE_SUBTREE, filter, NULL, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &res)) != LDAP_SUCCESS) {
#if LDAP_API_VERSION > 3003
		ldap_unbind_ext(ldapsession, NULL, NULL);
#else	
		ldap_unbind(ldapsession);
#endif
	        return NULL;
	}
	
	for (entry = ldap_first_entry(ldapsession,res); entry!=NULL && count<ldap_count_messages(ldapsession, res); entry=ldap_next_entry(ldapsession, res)) {
		count++;
		dn = ldap_get_dn(ldapsession, entry);
		return dn;
	};
	ldap_msgfree(res);
#if LDAP_API_VERSION > 3003
	ldap_unbind_ext(ldapsession, NULL, NULL);
#else	
	ldap_unbind(ldapsession);
#endif

	return NULL;
}


static char*
check_ldap_user(char *user, unsigned char *pass, const char *ldap_authorization_basedn) {
	LDAP *ldapsession;
	LDAPMessage *res, *entry;
	BerElement * ber;
	struct berval **list_of_values;
        struct berval value;
	char *attr;
	int rc, tls_version, count = 0;
	char filter[MAXFILTERSTR];
	char logbuf[MAXLOGBUF];
	char *userdn, *validgroups, *fn;

	/* Init LDAP */
	if(ldap_initialize(&ldapsession, ldap_authorization_host))
	{
		ldap_log(LOG_ERR, "Ldap connection initialize return fail status");
		return NULL;
	}

	/* Start TLS if we need it*/
	if (ldap_authorization_tls) {
		tls_version = LDAP_VERSION3;
		ldap_set_option(ldapsession, LDAP_OPT_PROTOCOL_VERSION, &tls_version);
		if((rc = ldap_start_tls_s(ldapsession, NULL,NULL))!=LDAP_SUCCESS)
		{
		    snprintf(logbuf, MAXLOGBUF, "Ldap start TLS error: %s", ldap_err2string(rc));	
		    ldap_log(LOG_WARNING, logbuf);
		    memset(logbuf, 0, MAXLOGBUF);
		}
	}

	/* Check authorization */
	if ((userdn = get_full_user_path(user, ldap_authorization_basedn))==NULL) {
		snprintf(logbuf, MAXLOGBUF, "User %s not fount in LDAP catalog (basedn=%s)", user, ldap_authorization_basedn);	
		ldap_log(LOG_DEBUG, logbuf);
		return NULL;
	}
#if LDAP_API_VERSION > 3003
	struct berval cred;
	struct berval *msgidp=NULL;
	cred.bv_len = strlen((const char *)pass);
	strcpy(cred.bv_val, (const char *)pass, cred.bv_len);
	if((rc = ldap_sasl_bind_s(ldapsession, userdn, "DIGEST-MD5", &cred, NULL, NULL, &msgidp))!=LDAP_SUCCESS) {
#else	
	if((rc = ldap_simple_bind_s(ldapsession, userdn, pass))!=LDAP_SUCCESS) {
#endif
		snprintf(logbuf, MAXLOGBUF, "Ldap authentificate failed: %s", ldap_err2string(rc)); 	
		ldap_log(LOG_DEBUG, logbuf); 
		return NULL;
	};

	/* create filter for search */
	memset(filter, 0, 100);
	snprintf(filter, MAXLOGBUF, "(&(objectClass=posixGroup)(memberUid=%s))", user);

	if ((rc = ldap_search_ext_s(ldapsession, ldap_authorization_basedn, LDAP_SCOPE_SUBTREE, filter, NULL, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &res)) != LDAP_SUCCESS) {
#if LDAP_API_VERSION > 3003
		ldap_unbind_ext(ldapsession, NULL, NULL);
#else	
		ldap_unbind(ldapsession);
#endif
	        return NULL;
	}
	
	for (entry = ldap_first_entry(ldapsession,res); entry!=NULL && count<ldap_count_messages(ldapsession, res); entry=ldap_next_entry(ldapsession, res)) {
		count++;
		for(attr = ldap_first_attribute(ldapsession,entry,&ber); attr != NULL ; attr=ldap_next_attribute(ldapsession,entry,ber)) {
			snprintf(logbuf, MAXLOGBUF, "Found attribute %s", attr); 	
			ldap_log(LOG_DEBUG, logbuf); 
			if (strcmp(attr, "cn"))
				continue;
			if ((list_of_values = ldap_get_values_len(ldapsession, entry, attr)) != NULL ) {
				value = *list_of_values[0];
				char temp[MAXGROUPLIST];
				memset(temp, 0, MAXGROUPLIST);
				strcpy(temp, ldap_authorization_validgroups);
				validgroups = strtok(temp, ",");
				while (validgroups != NULL)
				{
				    snprintf(logbuf, MAXLOGBUF, "Attribute value validgroups ? value.bv_val >> %s ? %s", validgroups, value.bv_val); 	
				    ldap_log(LOG_DEBUG, logbuf); 
				    if (!strcmp(validgroups, value.bv_val))
				    {
					ldap_msgfree(res);
#if LDAP_API_VERSION > 3003
					ldap_unbind_ext(ldapsession, NULL, NULL);
#else	
					ldap_unbind(ldapsession);
#endif
					fn = (char *)malloc(strlen(value.bv_val));
					strcpy(fn, value.bv_val);
					return fn;
				    }
				    validgroups = strtok (NULL, ",");
				}
//				printf("VAL: %s\n", value.bv_val);
				ldap_value_free_len( list_of_values );
			}
		}
	};
	ldap_msgfree(res);
#if LDAP_API_VERSION > 3003
	ldap_unbind_ext(ldapsession, NULL, NULL);
#else	
	ldap_unbind(ldapsession);
#endif

	return NULL;
}

static int
auth_ldap_server (MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info)
{
    unsigned char *pkt;
    char *authas;
    int pkt_len;
    char auth_string[MAXAUTHSTR];
    char logbuf[MAXLOGBUF];

    memset(logbuf, 0, MAXLOGBUF);
    memset(auth_string, 0, MAXAUTHSTR);
	   
    if ((pkt_len= vio->read_packet(vio, &pkt)) < 0)
	return CR_ERROR;
	     
    if (!pkt_len || *pkt == '\0')
    {
	ldap_log(LOG_DEBUG, "Empty password is not allowed for this plugin!");
	info->password_used= PASSWORD_USED_NO;
	return CR_ERROR;
    }

    info->password_used= PASSWORD_USED_YES;

    /* Check parametrs */
    if (!ldap_authorization_host)
    {
	ldap_log(LOG_ERR, "Config node \"ldap_authorization_host\" isn't correct");
	return CR_ERROR;
    }
    /* Search same parametrs in LDAP*/
/*    if (!ldap_authorization_basedn) {
	ldap_log(LOG_INFO, "BaseDN for LDAP search is not set!");
	return CR_ERROR;
    };
*/
    if (!ldap_authorization_binddn) {
	ldap_log(LOG_ERR, "BindDN for LDAP is not set!");
	return CR_ERROR;
    };

    if (!ldap_authorization_bindpasswd) {
	ldap_log(LOG_ERR, "BindPassword for LDAP is not set!");    
	return CR_ERROR;
    };

    if (strnlen(info->auth_string, MAXAUTHSTR)>MINAUTHSTR) {
	if((authas = (char *)check_ldap_user(info->user_name, pkt, info->auth_string))==NULL)
	    return CR_ERROR;
    } else {
	if((authas = (char *)check_ldap_user(info->user_name, pkt, "dc=ru"))==NULL)
	    return CR_ERROR;
    }
   
    strcpy(info->authenticated_as, (const char *)authas);
    snprintf(logbuf, MAXLOGBUF, "Login SUCCESS. User=%s as %s", info->user_name, authas); 	
    ldap_log(LOG_ERR, logbuf); 
    //strcpy(info->external_user, info->user_name);
    free(authas);
    return CR_OK;
}
 
static int
ldap_authorization_init(void *p) {
    /* FIXME */	
    char *mycnf[] = {
    	"/usr/local/etc/my.cnf",
	"/etc/my.cnf",
	"/var/db/mysql/my.cnf",
	"/usr/local/mysql/my.cnf",
	NULL
    };
    char logbuf[MAXLOGBUF];
    FILE *f;
    char str[MAXCFGLINE];
    int  res=0, mysect=0, i=0, len=0;
    char variable[MAXCFGLINE/2];
    char value[MAXCFGLINE/2];
    char *config = NULL;

    memset(logbuf, 0, MAXLOGBUF);

    for (i=0; mycnf[i]; i++) {
	    if (access(mycnf[i], R_OK)==0) {
		    config = mycnf[i];
		    break;
	    };
    }
    snprintf(logbuf, MAXLOGBUF, "Config found:%s", config);     
    ldap_log(LOG_DEBUG, logbuf);
    memset(logbuf, 0, MAXLOGBUF);
    if (!config)
	    return 0;

    f = fopen(config, "r");
    while (!feof(f)) {
	    if (fgets(str, MAXCFGLINE, f)!=NULL)
	    {
		res = sscanf(str, "%[^ ^\t^\n^=#] = %[^\t^\n;#]", variable, value);    
		if (!res || variable[0]=='#') continue;
		if (res==1 && variable[0]=='[' && variable[strlen(variable)-1] == ']') {
		    if (strcmp(variable, "[mysqld]"))
		    {
		        mysect = 0;
		        continue;
		    }
		    else 
		        mysect = 1;
		    printf("%s\n", variable);
		    continue;
		 } else if (res==1)
		    continue;
		 if (mysect) {
		    len = strlen(value);
		    for (i=0;i<len;i++)
		    {
		        if ((value[i]=='\'' || value[i]=='\"') && i < len-1) {
			    value[i]=value[i+1];
			    value[i+1] = '\'';
			    continue;
			};
		    }
		    i = len-1;
		    while (value[i]=='\'') {
		        value[i]='\0';
		        i--;
		    }
		    if (!strcmp(variable, "ldap_authorization_host")) {
			    snprintf(logbuf, MAXLOGBUF, "Config set: variable:%s value:%s", variable, value);	
			    ldap_log(LOG_DEBUG, logbuf);
			    memset(logbuf, 0, MAXLOGBUF);
			    strncpy(ldap_authorization_host, value, strnlen(value, MAXCFGLINE/2));
			    continue;
		    }
		    if (!strcmp(variable, "ldap_authorization_port")) {
			    snprintf(logbuf, MAXLOGBUF, "Config set: variable:%s value:%s", variable, value);	
			    ldap_log(LOG_DEBUG, logbuf);
			    memset(logbuf, 0, MAXLOGBUF);
			    ldap_authorization_port = atoi(value); 
			    continue;
		    }
		    if (!strcmp(variable, "ldap_authorization_validgroups")) {
			    snprintf(logbuf, MAXLOGBUF, "Config set: variable:%s value:%s", variable, value);	
			    ldap_log(LOG_DEBUG, logbuf);
			    memset(logbuf, 0, MAXLOGBUF);
			    strncpy(ldap_authorization_validgroups, value, strnlen(value, MAXCFGLINE/2));
			    continue;
		    }
		    if (!strcmp(variable, "ldap_authorization_binddn")) {
			    snprintf(logbuf, MAXLOGBUF, "Config set: variable:%s value:%s", variable, value);	
			    ldap_log(LOG_DEBUG, logbuf);
			    memset(logbuf, 0, MAXLOGBUF);
			    strncpy(ldap_authorization_binddn, value, strnlen(value, MAXCFGLINE/2));
			    continue;
		    }
		    if (!strcmp(variable, "ldap_authorization_bindpasswd")) {
			    snprintf(logbuf, MAXLOGBUF, "Config set: variable:%s value:%s", variable, value);	
			    ldap_log(LOG_DEBUG, logbuf);
			    memset(logbuf, 0, MAXLOGBUF);
			    strncpy(ldap_authorization_bindpasswd, value, strnlen(value, MAXCFGLINE/2));
			    continue;
		    }
		    if (!strcmp(variable, "ldap_authorization_defaultfilter")) {
			    snprintf(logbuf, MAXLOGBUF, "Config set: variable:%s value:%s", variable, value);	
			    ldap_log(LOG_DEBUG, logbuf);
			    memset(logbuf, 0, MAXLOGBUF);
			    strncpy(ldap_authorization_defaultfilter, value, strnlen(value, MAXCFGLINE/2));
			    continue;
		    }
		    if (!strcmp(variable, "ldap_authorization_timeout")) { 
			    snprintf(logbuf, MAXLOGBUF, "Config set: variable:%s value:%s", variable, value);	
			    ldap_log(LOG_DEBUG, logbuf);
			    memset(logbuf, 0, MAXLOGBUF);
			    ldap_authorization_timeout = atoi(value);
			    continue;
		    }
		    if (!strcmp(variable, "ldap_authorization_tls")) 
		    {
			    snprintf(logbuf, MAXLOGBUF, "Config set: variable:%s value:%s", variable, value);	
			    ldap_log(LOG_DEBUG, logbuf);
			    memset(logbuf, 0, MAXLOGBUF);
			    if (!strcmp(value, "ON"))
			    {
				    ldap_authorization_tls = 1;
				    continue;
			    } else if (!strcmp(value, "OFF"))
				    continue;
			    ldap_authorization_tls = atoi(value);
			    if (ldap_authorization_tls != 1) {
				    ldap_authorization_tls = 0;
				    continue;
			    }
		    }
		    if (!strcmp(variable, "ldap_authorization_debug")) 
		    {
			    snprintf(logbuf, MAXLOGBUF, "Config set: variable:%s value:%s", variable, value);	
			    ldap_log(LOG_DEBUG, logbuf);
			    memset(logbuf, 0, MAXLOGBUF);
			    if (!strcmp(value, "ON"))
			    {
				    ldap_authorization_debug = 1;
				    continue;
			    } else if (!strcmp(value, "OFF"))
				    continue;
			    ldap_authorization_debug = atoi(value);
			    if (ldap_authorization_debug != 1) {
				    ldap_authorization_debug = 0;
				    continue;
			    }
		    }
		}
	    }   
    }
    fclose(f);
    return 0;	
}

static MYSQL_SYSVAR_STR(auth_host, ldap_authorization_host,
		  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC,
		    "LDAP server's host address",
		      NULL, NULL, "ldap://127.0.0.1");

static MYSQL_SYSVAR_UINT(port, ldap_authorization_port,
		  PLUGIN_VAR_RQCMDARG,
		  "LDAP server's port. 389 by default",
		  NULL, NULL, 0, 0, 65535, 0);

/*static MYSQL_SYSVAR_STR(basedn, ldap_authorization_basedn,
		  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC,
		    "BaseDN if our domain in LDAP.",
		      NULL, NULL, "dc=example,dc=net");
*/
static MYSQL_SYSVAR_STR(validgroups, ldap_authorization_validgroups,
		  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC,
		    "List of valid groups for current mysql node.",
		      NULL, NULL, "users,administrators,mysqlgroups");

static MYSQL_SYSVAR_STR(binddn, ldap_authorization_binddn,
		  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC,
		    "Login who can get access to LDAP catalog.",
		      NULL, NULL, "cn=test,ou=users,dc=example,dc=net");

static MYSQL_SYSVAR_STR(bindpasswd, ldap_authorization_bindpasswd,
		  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC,
		    "Password for login from ldap_binddn.",
		      NULL, NULL, "mypassword");

static MYSQL_SYSVAR_STR(defaultfilter, ldap_authorization_defaultfilter,
		  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC,
		    "Filter for limit search in LDAP catalog.",
		      NULL, NULL, "(())");

static MYSQL_SYSVAR_UINT(timeout, ldap_authorization_timeout,
		  PLUGIN_VAR_RQCMDARG,
		  "Timeout for get answer from LDAP.",
		  NULL, NULL, 0, 0, 60, 0);

static MYSQL_SYSVAR_BOOL(tls, ldap_authorization_tls,
		  PLUGIN_VAR_OPCMDARG,
		  "Use TLS for LDAP connection (disable by default).",
		  NULL,                         // check
		  NULL,                         // update
		  0);

static MYSQL_SYSVAR_BOOL(debug, ldap_authorization_debug,
		  PLUGIN_VAR_RQCMDARG,
		  "Debug output from LDAP plugin.",
		  NULL, 
		  NULL,
		  0);

static struct st_mysql_sys_var* 
ldap_authorization_variables[]= {
    MYSQL_SYSVAR(auth_host),
    MYSQL_SYSVAR(port),
/*    MYSQL_SYSVAR(basedn),*/
    MYSQL_SYSVAR(validgroups),
    MYSQL_SYSVAR(binddn),
    MYSQL_SYSVAR(bindpasswd),
    MYSQL_SYSVAR(defaultfilter),
    MYSQL_SYSVAR(timeout),
    MYSQL_SYSVAR(tls),
    MYSQL_SYSVAR(debug),
    NULL
};

static struct st_mysql_auth ldap_handler =
{
  MYSQL_AUTHENTICATION_INTERFACE_VERSION,
  "ldap_authorization",                 /* required client-side plugin name */
  auth_ldap_server			/* server-side plugin main function */
};

mysql_declare_plugin(ldap_authorization)
{
  MYSQL_AUTHENTICATION_PLUGIN,
  &ldap_handler,                        /* type-specific descriptor */
  "ldap_authorization",                 /* plugin name */
  "Stanislav Putrya",                   /* author */
  "MySQL LDAP authorization plugin",	/* description */
  PLUGIN_LICENSE_BSD,                   /* license type */
  ldap_authorization_init,              /* init function */
  NULL,                                 /* no deinit function */
  0x0100,                               /* version = 1.0 */
  NULL,                                 /* no status variables */
  ldap_authorization_variables,         /* system variables */
  NULL,                                 /* no reserved information */
  0                                     /* no flags */
}
mysql_declare_plugin_end;

static int 
auth_ldap_client (MYSQL_PLUGIN_VIO *vio, MYSQL *mysql)
{
	int res;
	res= vio->write_packet(vio, (const unsigned char *) mysql->passwd, 
			strlen(mysql->passwd) + 1);

	return res ? CR_ERROR : CR_OK;
}

mysql_declare_client_plugin(AUTHENTICATION)
    "ldap_authorization",                        /* plugin name */
    "Stanislav Putrya",                        /* author */
    "MySQL LDAP authorization plugin", /* description */
    {1,0,0},                              /* version = 1.0.0 */
    "BSD",                                /* license type */
    NULL,                                 /* for internal use */
    NULL,                                 /* no init function */
    NULL,                                 /* no deinit function */
    NULL,                                 /* no option-handling function */
    auth_ldap_client                    /* main function */
mysql_end_client_plugin;

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

#define RETURN_TRUE     0
#define RETURN_FALSE    1

#define LDAP_DEFAULT_NETTIMEOUT 5

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

typedef struct {
    LDAP *sess;
} LD_session;

static char *ldap_authorization_host = 0;	    /* 127.0.0.1 */
static unsigned int ldap_authorization_port = 0;   /* 3389 */
static char *ldap_authorization_validgroups = 0;    /* */
static char *ldap_authorization_basedn = 0;
static char *ldap_authorization_binddn = 0;
static char *ldap_authorization_bindpasswd = 0;
static char *ldap_authorization_defaultfilter = 0;
static char *ldap_authorization_type = NULL;
static unsigned int ldap_authorization_network_timeout = LDAP_DEFAULT_NETTIMEOUT;
static unsigned int ldap_authorization_protocol_version = LDAP_VERSION3;
static char ldap_authorization_tls = 0;
static char ldap_authorization_debug = 0;

static void
ldap_log(int priority, char *msg)
{
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

static int
init_ldap_connection(LD_session *session, char *ldap_host) {
/* Init LDAP */
#ifdef LDAP_API_FEATURE_X_OPENLDAP      
	if (ldap_host != NULL && strchr(ldap_host, '/')) 
	{
		if(ldap_initialize(&session->sess, ldap_host)!=LDAP_SUCCESS)
		{
			ldap_log(LOG_ERR, "Ldap connection initialize return fail status");
			return RETURN_FALSE;
		}
	} else {
    #if LDAP_API_VERSION>3000
		ldap_log(LOG_ERR, "Ldap connection initialize return fail status");
		return RETURN_FALSE;
    #else
		session->sess = ldap_init(ldap_host, &ldap_authorization_port);
    #endif
	}
#else
	session->sess = ldap_open(ldap_host, ldap_authorization_port);
#endif
	if (session->sess == NULL) 
	{
		ldap_log(LOG_ERR, "Final check: Ldap connection initialize return fail status");
		return RETURN_FALSE;
	}
	return RETURN_TRUE;
}

static int
set_ldap_options(LD_session *session) {
	struct timeval timeout;
	int rc = 0;
	char logbuf[MAXLOGBUF];

	timeout.tv_sec = ldap_authorization_network_timeout;
	timeout.tv_usec = FALSE;
	ldap_set_option(session->sess, LDAP_OPT_PROTOCOL_VERSION, &ldap_authorization_protocol_version);
	ldap_set_option(session->sess, LDAP_OPT_NETWORK_TIMEOUT, &timeout);

	/* Start TLS if we need it*/
	if (ldap_authorization_tls) {
		if((rc = ldap_start_tls_s(session->sess, NULL,NULL))!=LDAP_SUCCESS)
		{
			snprintf(logbuf, MAXLOGBUF, "Ldap start TLS error: %s. ", ldap_err2string(rc));     
			ldap_log(LOG_WARNING, logbuf);
		}
	}
	return RETURN_TRUE;
}

int
ldap_get_fulldn(LD_session *session, char *username, char *userstr, int username_length)
{
	struct berval cred;
	char filter[MAXFILTERSTR], *dn;
	int rc = 0;
	char logbuf[MAXLOGBUF];
	LDAPMessage *res, *entry;

	memset(userstr, 0, username_length);

	cred.bv_val = ldap_authorization_bindpasswd;
	cred.bv_len = strlen(ldap_authorization_bindpasswd);
#if LDAP_API_VERSION > 3000	
	if((rc = ldap_sasl_bind_s(session->sess, ldap_authorization_binddn, ldap_authorization_type, &cred, NULL, NULL, NULL))!=LDAP_SUCCESS) {


		snprintf(logbuf, MAXLOGBUF, "Ldap server %s authentificate with method %s failed: %s", ldap_authorization_host, ldap_authorization_type, ldap_err2string(rc));  
		ldap_log(LOG_DEBUG, logbuf);
		return RETURN_FALSE;
	};
#else	
	if((rc = ldap_bind_s(session->sess, ldap_authorization_binddn, ldap_authorization_bindpasswd, LDAP_AUTH_SIMPLE))!=LDAP_SUCCESS) {
		snprintf(logbuf, MAXLOGBUF, "Ldap server %s authentificate failed: %s", ldap_authorization_host, ldap_err2string(rc));  
		ldap_log(LOG_DEBUG, logbuf);
		return RETURN_FALSE;
	}
#endif		
	/* create filter for search */
	memset(filter, 0, MAXFILTERSTR);
	snprintf(filter, MAXLOGBUF, "(uid=%s)", username);

	if ((rc = ldap_search_ext_s(session->sess, (const char *)ldap_authorization_basedn, LDAP_SCOPE_SUBTREE, filter, NULL, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &res)) != LDAP_SUCCESS) {
#if LDAP_API_VERSION > 3000
		ldap_unbind_ext(session->sess, NULL, NULL);
#else   
		ldap_unbind(session->sess);
#endif
		return RETURN_FALSE;
	}
	if ((entry = ldap_first_entry(session->sess,res)) == NULL) {
		return RETURN_FALSE;
	} else {
		dn = ldap_get_dn(session->sess, entry);
		strncpy(userstr, dn, strlen(dn));
	};
	ldap_msgfree(res);
	return RETURN_TRUE;
}

static char*
check_ldap_auth(LD_session *session, char *login, unsigned char *password, char *fullname) {
	int rc = 0, count = 0;
	char logbuf[MAXLOGBUF];
	LDAPMessage *res, *entry;
	char *attr, *dn;
	BerElement * ber;
	struct berval **list_of_values;
	struct berval value;
	char *validgroups;
	char filter[MAXFILTERSTR];
	struct berval cred_user;

	/* Check authorization */
	memset(filter, 0, 100);
	snprintf(filter, MAXLOGBUF, "(&(objectClass=posixGroup)(memberUid=%s))", login);


	cred_user.bv_val = (const char *)password;
	cred_user.bv_len = strlen(cred_user.bv_val);

#if LDAP_API_VERSION > 3000	
	if((rc = ldap_sasl_bind_s(session->sess, fullname, ldap_authorization_type, &cred_user, NULL, NULL, NULL))!=LDAP_SUCCESS) {
		snprintf(logbuf, MAXLOGBUF, "Ldap server %s authentificate with method %s failed: %s", ldap_authorization_host, ldap_authorization_type, ldap_err2string(rc));  
		ldap_log(LOG_DEBUG, logbuf);
		return RETURN_TRUE;
	};
#else	
	if((rc = ldap_bind_s(session->sess, fullname, password, LDAP_AUTH_SIMPLE))!=LDAP_SUCCESS) {
		snprintf(logbuf, MAXLOGBUF, "Ldap server %s authentificate failed: %s", ldap_authorization_host, ldap_err2string(rc));  
		ldap_log(LOG_DEBUG, logbuf);
		return RETURN_TRUE;
	}
#endif

	if ((rc = ldap_search_ext_s(session->sess, ldap_authorization_basedn, LDAP_SCOPE_SUBTREE, filter, NULL, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &res)) != LDAP_SUCCESS) {
#if LDAP_API_VERSION > 3000
		ldap_unbind_ext(session->sess, NULL, NULL);
#else   
		ldap_unbind(session->sess);
#endif
		return RETURN_TRUE;
	}

	for (entry = ldap_first_entry(session->sess,res); entry!=NULL && count<=ldap_count_messages(session->sess, res); entry=ldap_next_entry(session->sess, res)) {
		count++;
		for(attr = ldap_first_attribute(session->sess,entry,&ber); attr != NULL ; attr=ldap_next_attribute(session->sess,entry,ber)) {
			snprintf(logbuf, MAXLOGBUF, "Found attribute %s", attr);        
			ldap_log(LOG_DEBUG, logbuf); 
			if (strcmp(attr, "cn"))
				continue;
			if ((list_of_values = ldap_get_values_len(session->sess, entry, attr)) != NULL ) {
				value = *list_of_values[0];
				char temp[MAXGROUPLIST];
				memset(temp, 0, MAXGROUPLIST);
				if (ldap_authorization_validgroups) {
					strcpy(temp, ldap_authorization_validgroups);
					validgroups = strtok(temp, ",");
					while (validgroups != NULL)
					{
						snprintf(logbuf, MAXLOGBUF, "Attribute value validgroups ? value.bv_val >> %s ? %s", validgroups, value.bv_val);        
						ldap_log(LOG_DEBUG, logbuf); 
						if (!strcmp(validgroups, value.bv_val))
						{
							ldap_msgfree(res);
#if LDAP_API_VERSION > 3000
							ldap_unbind_ext(session->sess, NULL, NULL);
#else   
							ldap_unbind(session->sess);
#endif
							dn = malloc((int)strlen(value.bv_val)*sizeof(char));
							memset(dn, 0, (int)strlen(value.bv_val)*sizeof(char));
							strcpy(dn, value.bv_val);
							return dn;
						}
						validgroups = strtok (NULL, ",");
					}
//					printf("VAL: %s\n", value.bv_val);
					ldap_value_free_len( list_of_values );
				}
			}
		}
		res = ldap_next_message(session->sess, res);
	};
	ldap_msgfree(res);
#if LDAP_API_VERSION > 3000
	ldap_unbind_ext(session->sess, NULL, NULL);
#else   
	ldap_unbind(session->sess);
#endif
	return RETURN_TRUE;
}

int
auth_ldap_server (MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info)
{
    unsigned char *pkt;
    char *authas = NULL, *ldap_host = NULL;
    int pkt_len, num_gopt = 0;
    int last_error = 0;
    char auth_string[MAXAUTHSTR];
    char logbuf[MAXLOGBUF];
    LD_session ldap_session;

    ldap_session.sess = NULL;

    memset(logbuf, 0, MAXLOGBUF);
    memset(auth_string, 0, MAXAUTHSTR);
	   
    if ((pkt_len= vio->read_packet(vio, &pkt)) < 0)
    {
	ldap_log(LOG_ERR, "Read vio packet error");
	return CR_ERROR;
    }
	     
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
    };

    if (!ldap_authorization_binddn) {
	ldap_log(LOG_ERR, "BindDN for LDAP is not set!");
	return CR_ERROR;
    };

    if (!ldap_authorization_bindpasswd) {
	ldap_log(LOG_ERR, "BindPassword for LDAP is not set!");    
	return CR_ERROR;
    };

    if (!ldap_authorization_basedn) {
	ldap_log(LOG_ERR, "BaseDN for LDAP is not set!");    
	return CR_ERROR;
    }

    char ldap_hosts[MAXGROUPLIST];
    memset(ldap_hosts, 0, MAXGROUPLIST);
    strcpy(ldap_hosts, ldap_authorization_host);
    ldap_host = strtok(ldap_hosts, ",");

    while (ldap_host != NULL)
    {
	if (init_ldap_connection(&ldap_session, ldap_host) == RETURN_FALSE) { 
	    snprintf(logbuf, MAXLOGBUF, "LDAP Initialisation connect with host %s return error status. Exiting...", ldap_host); 	
	    ldap_log(LOG_DEBUG, logbuf); 
	    ldap_host = strtok (NULL, ",");
	    continue;
	}; 

	if (set_ldap_options(&ldap_session) == RETURN_FALSE) {
	    ldap_log(LOG_ERR, "LDAP Set options return error status. Exiting...");
	    ldap_host = strtok (NULL, ",");
	    continue;
	};

	if (ldap_get_fulldn(&ldap_session, info->user_name, auth_string, MAXAUTHSTR) == RETURN_FALSE) {
	    ldap_get_option(ldap_session.sess, LDAP_OPT_ERROR_NUMBER, &last_error);
	    if (last_error == LDAP_SERVER_DOWN) {
		    num_gopt = 0;
		    snprintf(logbuf, MAXLOGBUF, "Connect with server %s timed out.", ldap_host); 	
		    ldap_log(LOG_DEBUG, logbuf); 
		    ldap_host = strtok (NULL, ",");
		    continue;
	    }
	    ldap_log(LOG_ERR, "LDAP User isn't found in catalog. Exiting...");
	    return CR_ERROR;
	}

	if ((authas = check_ldap_auth(&ldap_session, info->user_name, pkt, auth_string)) == RETURN_TRUE) {
	    ldap_get_option(ldap_session.sess, LDAP_OPT_ERROR_NUMBER, &last_error);
	    if (last_error == LDAP_SERVER_DOWN) {
		    snprintf(logbuf, MAXLOGBUF, "Connect with server %s timed out.", ldap_host); 	
		    ldap_log(LOG_DEBUG, logbuf); 
		    ldap_host = strtok (NULL, ",");
		    continue;
	    }
	    snprintf(logbuf, MAXLOGBUF, "Auth user name or password isn't correct (dn addr: %p). Exiting...", authas);
	    ldap_log(LOG_ERR, logbuf);
	    return CR_ERROR;
	} else {
	    num_gopt++;
	    break;
	};
	return CR_ERROR;
    }

    if (!num_gopt) return CR_ERROR;

    snprintf(logbuf, MAXLOGBUF, "Login SUCCESS. User=%s as %s", info->user_name, authas); 	
    ldap_log(LOG_DEBUG, logbuf); 
    strcpy(info->external_user, info->user_name);
    strcpy(info->authenticated_as, authas);
    free(authas);
    //strcpy(info->external_user, info->user_name);
    return CR_OK;
};
 
int
ldap_authorization_init(void *p) {
    return 0;	
};

static MYSQL_SYSVAR_STR(auth_host, ldap_authorization_host,
		  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC,
		    "LDAP server's host address",
		      NULL, NULL, "ldap://127.0.0.1");

static MYSQL_SYSVAR_UINT(port, ldap_authorization_port,
		  PLUGIN_VAR_RQCMDARG,
		  "LDAP server's port. 389 by default",
		  NULL, NULL, 389, 0, 65535, 0);

static MYSQL_SYSVAR_STR(validgroups, ldap_authorization_validgroups,
		  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC,
		    "List of valid groups for current mysql node.",
		      NULL, NULL, "users,administrators,mysqlgroups");

static MYSQL_SYSVAR_STR(basedn, ldap_authorization_basedn,
		  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC,
		    "BaseDN for LDAP catalog.",
		      NULL, NULL, "dc=example,dc=net");

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
		      NULL, NULL, "");

static MYSQL_SYSVAR_UINT(timeout, ldap_authorization_network_timeout,
		  PLUGIN_VAR_RQCMDARG,
		  "Timeout for get answer from LDAP.",
		  NULL, NULL, 5, 0, 60, 0);

static MYSQL_SYSVAR_UINT(protocol_version, ldap_authorization_protocol_version,
		  PLUGIN_VAR_RQCMDARG,
		  "Protocol version of LDAP catalog.",
		  NULL, NULL, 3, 0, 3, 0);

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
    MYSQL_SYSVAR(validgroups),
    MYSQL_SYSVAR(binddn),
    MYSQL_SYSVAR(basedn),
    MYSQL_SYSVAR(bindpasswd),
    MYSQL_SYSVAR(defaultfilter),
    MYSQL_SYSVAR(timeout),
    MYSQL_SYSVAR(protocol_version),
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

int 
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

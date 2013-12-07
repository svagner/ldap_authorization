#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <ldap.h>

#define RETURN_TRUE	0
#define RETURN_FALSE	1

#define TRUE	1
#define FALSE	0

#define LDAP_DEFAULT_NETTIMEOUT 5

#define MAXLOGBUF	256
#define MAXLOGBUFEX	512
#define MAXFILTERSTR	128
#define MAXAUTHSTR	128
#define MINAUTHSTR	3
#define MAXCFGLINE	1024
#define MAXGROUPLIST	512	
#define CR_ERROR	1
#define CR_OK		0

#if !defined(__attribute__) && (defined(__cplusplus) || !defined(__GNUC__)  || __GNUC__ == 2 && __GNUC_MINOR__ < 8)
#define __attribute__(A)
#endif

static char *ldap_authorization_host = "ldap://ldap.bsdway.ru";	    /* 127.0.0.1 */
static long ldap_authorization_port = 389;   /* 389 */
static char *ldap_authorization_validgroups = "mysql_admins";    /* */
static char *ldap_authorization_binddn = "cn=readonly,dc=bsdway,dc=ru";
static char *ldap_authorization_bindpasswd = "jhgjhgasdjhgjhg";
static char *ldap_authorization_basedn = "dc=bsdway,dc=ru";
static char *ldap_authorization_defaultfilter = "";
static char *ldap_authorization_type = NULL;
static unsigned int ldap_authorization_timeout = 20;
static unsigned short ldap_protocol_version = LDAP_VERSION3;
static unsigned long ldap_network_timeout = LDAP_DEFAULT_NETTIMEOUT;
static char ldap_authorization_tls = TRUE;
static char ldap_authorization_debug = TRUE;

typedef struct {
	LDAP *sess;
} LD_session;

static void
ldap_log(int priority, char *msg)
{
  char *env = NULL;	
   printf("%s\n", msg);
};

static int
init_ldap_connection(LD_session *session) {
	/* Init LDAP */
#ifdef LDAP_API_FEATURE_X_OPENLDAP	
	if (ldap_authorization_host != NULL && strchr(ldap_authorization_host, '/')) 
	{
	    if(ldap_initialize(&session->sess, ldap_authorization_host)!=LDAP_SUCCESS)
	    {
		ldap_log(LOG_ERR, "Ldap connection initialize return fail status");
		return RETURN_FALSE;
	    }
	} else {
#if LDAP_API_VERSION>3000
		ldap_log(LOG_ERR, "Ldap connection initialize return fail status");
		return RETURN_FALSE;
#else
		session->sess = ldap_init(ldap_authorization_host, &ldap_authorization_port);
#endif
	}
#else
	session->sess = ldap_open(ldap_authorization_host, ldap_authorization_port);
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

	timeout.tv_sec = ldap_network_timeout;
	timeout.tv_usec = FALSE;
	ldap_set_option(session->sess, LDAP_OPT_PROTOCOL_VERSION, &ldap_protocol_version);
	ldap_set_option(session->sess, LDAP_OPT_NETWORK_TIMEOUT, &timeout);

	/* Start TLS if we need it*/
	if (ldap_authorization_tls) {
		if((rc = ldap_start_tls_s(session->sess, NULL,NULL))!=LDAP_SUCCESS)
		{
		    snprintf(logbuf, MAXLOGBUF, "Ldap start TLS error: %s. ", ldap_err2string(rc));	
		    ldap_log(LOG_WARNING, logbuf);
		}
	}
}

static int
ldap_get_fulldn(LD_session *session, char *username, char *userstr, int username_length)
{
	struct berval cred;
	struct berval *msgidp=NULL;
	char filter[MAXFILTERSTR], *dn;
	int rc = 0;
	char logbuf[MAXLOGBUF];
	LDAPMessage *res, *entry;

	memset(userstr, 0, username_length);

        cred.bv_val = ldap_authorization_bindpasswd;
        cred.bv_len = strlen(ldap_authorization_bindpasswd);

#if LDAP_API_VERSION > 3000
	if((rc = ldap_sasl_bind_s(session->sess, ldap_authorization_binddn, ldap_authorization_type, &cred, NULL, NULL, &msgidp))!=LDAP_SUCCESS) {
		snprintf(logbuf, MAXLOGBUF, "!!!Ldap server %s authentificate with method %s failed: %s", ldap_authorization_host, ldap_authorization_type, ldap_err2string(rc));	
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

	if ((rc = ldap_search_ext_s(session->sess, ldap_authorization_basedn, LDAP_SCOPE_SUBTREE, filter, NULL, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &res)) != LDAP_SUCCESS) {
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

static int
check_auth(LD_session *session, char *login, char *password, char *fullname) {
	int rc = 0, count = 0;
	char username[MAXFILTERSTR];
	char logbuf[MAXLOGBUF];
	LDAPMessage *res, *entry;
	char *attr;
	BerElement * ber;
        struct berval **list_of_values;
        struct berval value;
	char *userdn, *validgroups, *fn;
	char filter[MAXFILTERSTR];

	/* Check authorization */
	memset(filter, 0, 100);
	snprintf(filter, MAXLOGBUF, "(&(objectClass=posixGroup)(memberUid=%s))", login);

	struct berval cred;
	struct berval *msgidp=NULL;
	cred.bv_val = password;
	cred.bv_len = strlen(password);

#if LDAP_API_VERSION > 3000
	if((rc = ldap_sasl_bind_s(session->sess, fullname, ldap_authorization_type, &cred, NULL, NULL, NULL))!=LDAP_SUCCESS) {
		snprintf(logbuf, MAXLOGBUF, "Ldap server %s authentificate with method %s failed: %s", ldap_authorization_host, ldap_authorization_type, ldap_err2string(rc));	
		ldap_log(LOG_DEBUG, logbuf);
		return RETURN_FALSE;
	};
#else
	if((rc = ldap_bind_s(session->sess, fullname, password, LDAP_AUTH_SIMPLE))!=LDAP_SUCCESS) {
		snprintf(logbuf, MAXLOGBUF, "Ldap server %s authentificate failed: %s", ldap_authorization_host, ldap_err2string(rc));	
		ldap_log(LOG_DEBUG, logbuf);
		return RETURN_FALSE;
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
	
	for (entry = ldap_first_entry(session->sess,res); entry!=NULL && count<ldap_count_messages(session->sess, res); entry=ldap_next_entry(session->sess, res)) {
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
					    fn = (char *)malloc(strlen(value.bv_val));
					    strcpy(fn, value.bv_val);
					    return RETURN_TRUE;
					}
					validgroups = strtok (NULL, ",");
				    }
				    printf("VAL: %s\n", value.bv_val);
				    ldap_value_free_len( list_of_values );
				}
			}
		}
	};
	ldap_msgfree(res);
#if LDAP_API_VERSION > 3000
	ldap_unbind_ext(session->sess, NULL, NULL);
#else	
	ldap_unbind(session->sess);
#endif
	return RETURN_FALSE;
}

int
main ()
{
    unsigned char *pkt;
    char *authas;
    int i;
    char auth_string[MAXAUTHSTR], ch;
    char logbuf[MAXLOGBUF];
    LD_session ldap_session;

#define MAXINPLEN   100    
    char user[MAXINPLEN];
    char pass[MAXINPLEN];
    memset(pass, 0, MAXINPLEN);
    memset(user, 0, MAXINPLEN);

    printf("Enter the username: ");
    for(i=0;i<MAXINPLEN;i++)
    {
	    ch = getchar();
	    if (ch == '\n') break;
	    user[i] = ch;
    }

    user[i+1] = '\0';
    printf("Username: %s\n", user);

    printf("Enter the password <any characters>: ");
    for(i=0;i<MAXINPLEN;i++)
    {
	    ch = getchar();
	    if (ch == '\n') break;
	    pass[i] = ch;
    }

    pass[i+1] = '\0';

    /*If you want to know what you have entered as password, you can print it*/
    printf("Your password is: ");

    for(i=0;i<MAXINPLEN;i++)
    {
	    printf("%c",pass[i]);
    }
    printf("\n");

    ldap_session.sess = NULL;

    memset(logbuf, 0, MAXLOGBUF);
    memset(auth_string, 0, MAXAUTHSTR);
	   
    /* Check parametrs */
    if (!ldap_authorization_host)
    {
	ldap_log(LOG_ERR, "Config node \"ldap_authorization_host\" isn't correct");
	return CR_ERROR;
    }

    if (init_ldap_connection(&ldap_session) == RETURN_FALSE) {
	ldap_log(LOG_ERR, "LDAP Initialisation connect return error status. Exiting...");
	return CR_ERROR;
    };

    if (set_ldap_options(&ldap_session) == RETURN_FALSE) {
	ldap_log(LOG_ERR, "LDAP Set options return error status. Exiting...");
	return CR_ERROR;
    };

    if (ldap_get_fulldn(&ldap_session, user, auth_string, MAXAUTHSTR) == RETURN_FALSE) {
	ldap_log(LOG_ERR, "LDAP User isn't found in catalog. Exiting...");
	return CR_ERROR;
    }
    printf("%s\n", auth_string);

    if (check_auth(&ldap_session, user, pass, auth_string) == RETURN_FALSE) {
	ldap_log(LOG_ERR, "Auth user name or password isn't correct. Exiting...");
	return CR_ERROR;
    };

    snprintf(logbuf, MAXLOGBUF, "Login SUCCESS."); 	
    ldap_log(LOG_DEBUG, logbuf); 

    return CR_OK;
}
 

/*
 * JKSEngine v 1.0 - OpenSSL Engine for using Java Keystores with OpenSSL
 * Copyright (c) Andreas Gruener 2011. All rights reserved.
 *
 *
 * This file is part of JKSEngine.
 *
 * JKSEngine is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * JKSEngine is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with JKSEngine.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * File: Main File of JKSEngine
 */

/*
 * Standard Includes
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
#include <openssl/store.h>
#include <openssl/err.h>


/*
 * JKSEngine Specific Includes
 */
#include "JKSEngine.h"


/*
 * Global Variables
 */
int jksengine_ctx_index = -1;

int jksengine_digest_nids[] =
	{ NID_sha1, NID_sha224, NID_sha256, NID_sha384, NID_sha512, NID_md5,NID_ripemd160, NID_dsa,0 };

/*
 * Config Param
 */
static const ENGINE_CMD_DEFN jksengine_cmd_defn[] =
	{{0,"SO_PATH","Path Specification",ENGINE_CMD_FLAG_STRING},
	 {1,"ID","Engine ID",ENGINE_CMD_FLAG_STRING},
	 {2,"KeyStorePass","Java Keystore Password",ENGINE_CMD_FLAG_STRING},
	 {3,"JavaConnectorPath","Path to Java Connector Tool",ENGINE_CMD_FLAG_STRING},
	 {4,"KeyStoreProvider","Keystore Provider",ENGINE_CMD_FLAG_STRING},
	 {5,"Java","Java Executable",ENGINE_CMD_FLAG_STRING}
	};


/*
 * General Engine Initialisation and Configuration
 */

EVP_PKEY* jksengine_load_key(ENGINE *en, const char *key_id, UI_METHOD *ui_method, void *callback_data){
	EVP_PKEY *pubkey = NULL;
	JKSENGINE_CTX *jks_ctx = NULL;
	PW_DATA *pw_data = NULL;
	KEY_ID *kid = NULL;
	PARAMPAIR *ppair = NULL;


	DEBUG("FUNCTION_CALL: jksengine_load_key\n");

	// Store Keystore,Alias and Password (optional) in Context Information
	jks_ctx = ENGINE_get_ex_data(en,jksengine_ctx_index);
	if (!jks_ctx){
		ERR("ERROR: NULL Pointer to Engine Context Area\n");
		return NULL;
	}

	kid = parseKeyIdentifier(key_id);
	if (!kid){
		ERR("ERROR: NULL Pointer to Key Identifier\n");
		return NULL;
	}

	jks_ctx->privkeystore = BUF_strdup(kid->keystore);

	ppair = kid->params;
	while (ppair){
		if (!strcmp(ppair->key,"alias")){
			break;
		}
	}

	jks_ctx->privkeyalias = BUF_strdup(ppair->value);

	if ((!jks_ctx->privkeystore)||(!jks_ctx->privkeyalias)){
		ERR("ERROR: Memory Allocation Failed\n");
		return NULL;
	}

	// Get Password
	pw_data = (PW_DATA *)callback_data;

	if (pw_data){
		if (pw_data->password){
			pw_data->password = (const char *)pw_data->password;
			jks_ctx->keystorepass = OPENSSL_malloc(strlen(pw_data->password)*sizeof(char));
			if (!(jks_ctx->keystorepass)){
				ERR("ERROR: NO Memory for Saving Keystore Password\n");
				return NULL;
			}
			strncpy(jks_ctx->keystorepass,pw_data->password,strlen(pw_data->password));
		}
	}

	// Release Memory
	KEY_ID_free(kid);

	pubkey = getPublicKey(en);
	if (!pubkey){
		ERR("ERROR: Could Not Load PublicKey\n");
		return NULL;
	}

	return pubkey;
}

EVP_PKEY* jksengine_load_pubkey(ENGINE *e, const char *key_id, UI_METHOD *ui_method, void *callback_data){
	EVP_PKEY *pubkey = NULL;


	DEBUG("FUNCTION_CALL: jksengine_load_pubkey\n");

	pubkey = jksengine_load_key(e, key_id, ui_method, callback_data);
	if (!pubkey){
		ERR("ERROR: Loading key failed\n");
		return NULL;
	}

	return pubkey;
}

EVP_PKEY* jksengine_load_privkey(ENGINE *e, const char *key_id, UI_METHOD *ui_method, void *callback_data){
	EVP_PKEY *privkey = NULL;


	DEBUG("FUNCTION_CALL: jksengine_load_privkey\n");

	privkey = jksengine_load_key(e, key_id, ui_method, callback_data);
	if (!privkey){
		ERR("ERROR: Loading key failed\n");
		return NULL;
	}

	return privkey;
}

int jksengine_init(ENGINE *e){
	JKSENGINE_CTX *jks_ctx = NULL;

	DEBUG("FUNCTION_CALL: jksengine_init\n");

	// Ensure General Context Area
	jksengine_ctx_index = ENGINE_get_ex_new_index(0, NULL, NULL, NULL, 0);
	if (jksengine_ctx_index < 0){
		ERR("ERROR: No Engine Context Area Created\n");
		return 0;
	}
	// Get Memory
	jks_ctx = OPENSSL_malloc(sizeof(JKSENGINE_CTX));
	if (!jks_ctx){
		ERR("ERROR: No Memory for Context Area\n");
		return 0;
	}
	// Fill Memory with 0
	memset(jks_ctx, 0, sizeof(JKSENGINE_CTX));
	// Register Context Area to Area Index
	ENGINE_set_ex_data(e,jksengine_ctx_index,jks_ctx);

	// Set Default Values
	jks_ctx->connectorpath = strdup(STDCONNPATH);
	jks_ctx->keystoreprovider = strdup(STDKSPROVIDER);
	jks_ctx->keystorepass = strdup(STDPASS);
	jks_ctx->java = strdup(STDJAVA);

	return 1;
}

int jksengine_ctrl(ENGINE *e,int cmd, long i, void *p, void (*f)(void)){
	JKSENGINE_CTX *jks_ctx;


	DEBUG("FUNCTION_CALL: jksengine_ctrl\n");

	jks_ctx = ENGINE_get_ex_data(e,jksengine_ctx_index);
	if (!jks_ctx){
		ERR("ERROR: No Engine Context Area\n");
		return 0;
	}

	switch (cmd)
	{
		case CMDKEYSTOREPASS:
			OPENSSL_free((jks_ctx->keystorepass));
			jks_ctx->keystorepass = BUF_strdup((char*)p);
			break;
		case CMDCONNECTORPATH:
			OPENSSL_free((jks_ctx->connectorpath));
			jks_ctx->connectorpath = BUF_strdup((char*)p);
			break;
		case CMDKEYSTOREPROVIDER:
			OPENSSL_free((jks_ctx->keystoreprovider));
			jks_ctx->keystoreprovider = BUF_strdup((char*)p);
			break;
		case CMDJAVA:
			OPENSSL_free((jks_ctx->java));
			jks_ctx->java = BUF_strdup((char*)p);
			break;
		default:
			//error;
			break;
	}


	return 1;
}

int jksengine_finish(ENGINE *e){
	JKSENGINE_CTX *jks_ctx = NULL;


	DEBUG("FUNCTION_CALL: jksengine_finish\n");

	jks_ctx = ENGINE_get_ex_data(e, jksengine_ctx_index);
	ENGINE_set_ex_data(e, jksengine_ctx_index, NULL);

	if (!jks_ctx){
		ERR("ERROR: Could not get Context Area\n");
		return 0;
	}

	// Free Memory
	if (jks_ctx->keystorepass){
		OPENSSL_free(jks_ctx->keystorepass);
		jks_ctx->keystorepass = NULL;
	}
	OPENSSL_free(jks_ctx->privkeyalias);
	jks_ctx->privkeyalias = NULL;
	OPENSSL_free(jks_ctx->privkeystore);
	jks_ctx->privkeystore = NULL;
	OPENSSL_free(jks_ctx->connectorpath);
	jks_ctx->connectorpath = NULL;
	OPENSSL_free(jks_ctx->keystoreprovider);
	jks_ctx->keystoreprovider = NULL;
	OPENSSL_free(jks_ctx->java);
	jks_ctx->java = NULL;
	JKSENGINE_MD_GEN_CTX_free(jks_ctx->hash);
	OPENSSL_free(jks_ctx);
	jks_ctx = NULL;

	return 1;
}

int jksengine_destroy(ENGINE *e){
	DEBUG("FUNCTION_CALL: jksengine_destroy\n");

	return 1;
}

int jksengine_register_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid){
	DEBUG("FUNCTION_CALL: jksengine_register_digests\n");

	if(!digest){
		// Return list of supported Digests
		*nids = jksengine_digest_nids;
		return (sizeof(jksengine_digest_nids)-1)/sizeof(jksengine_digest_nids[0]);
	}
	// Return Specific Digest
	switch (nid){
		case NID_sha1:
			*digest = &digest_sha1;
			break;
		case NID_md5:
			*digest = &digest_md5;
			break;
		case NID_sha224:
			*digest = &digest_sha224;
			break;
		case NID_sha256:
			*digest = &digest_sha256;
			break;
		case NID_sha384:
			*digest = &digest_sha384;
			break;
		case NID_sha512:
			*digest = &digest_sha512;
			break;
		case NID_ripemd160:
			*digest = &digest_ripemd160;
			break;
		case NID_dsa:
			*digest = &digest_mddsa;
			break;
		default:
			*digest = NULL;
			return 0;
	}
	return 1;
}


int jksengine_bind(ENGINE *e){
	DEBUG("FUNCTION_CALL: jksengine_bind\n");

	if (jksengine_rsa_bind()){
		ERR("ERROR: Failed to Bind Public RSA Methods of OpenSSL");
		return 1;
	}

	if (jksengine_dsa_bind()){
		ERR("ERROR: Failed to Bind Public DSA Methods of OpenSSL");
		return 1;
	}

	if (jksengine_ecdsa_bind()){
		ERR("ERROR: Failed to Bind Public ECDSA Methods of OpenSSL");
		return 1;
	}

	if ((!ENGINE_set_id(e,"JKSEngine")) ||
		(!ENGINE_set_name(e,"OpenSSL Engine JKSEngine")) ||
		(!ENGINE_set_cmd_defns(e,jksengine_cmd_defn)) ||
		(!ENGINE_set_ctrl_function(e,jksengine_ctrl)) ||
		(!ENGINE_set_init_function(e,jksengine_init)) ||
		(!ENGINE_set_finish_function(e,jksengine_finish)) ||
		(!ENGINE_set_destroy_function(e,jksengine_destroy)) ||
		(!ENGINE_set_load_privkey_function(e,jksengine_load_privkey)) ||
		(!ENGINE_set_load_pubkey_function(e,jksengine_load_pubkey)) ||
		(!ENGINE_set_RSA(e,&jksengine_rsa_methods))||
		(!ENGINE_set_DSA(e,&jksengine_dsa_methods))||
		(!ENGINE_set_ECDSA(e,&jksengine_ecdsa_methods))||
		(!ENGINE_set_flags(e,ENGINE_FLAGS_BY_ID_COPY)) ||
		(!ENGINE_set_digests(e, jksengine_register_digests))) {
		ERR("ERROR: Engine bind failed");
		return 0;
	} else {
		return 1;
	}
}


ENGINE *engine_jksengine(void){
    ENGINE *e;

    DEBUG("FUNCTION_CALL: engine_jksengine\n");

    e = ENGINE_new();
    if (!e)
        return(NULL);
    if (!jksengine_bind(e)) {
        ENGINE_free(e);
        return(NULL);
    }
    return(e);
}


void ENGINE_load_jksengine(void){
    ENGINE *e;

    DEBUG("FUNCTION_CALL: ENGINE_load_jksengine\n");

    e = engine_jksengine();
    if (!e){
    	ERR("ERROR: No Engine Object created\n");
    	return;
    }
    else {
    	ENGINE_add(e);
    	ENGINE_free(e);
    	ERR_clear_error();
    }
}

int jksengine_bind_helper(ENGINE *e, const char *id){
	DEBUG("FUNCTION_CALL: jksengine_bind_helper\n");

    if (id && (strcmp(id, "JKSEngine") != 0))
        return(0);
    return jksengine_bind(e);
}


IMPLEMENT_DYNAMIC_CHECK_FN();

IMPLEMENT_DYNAMIC_BIND_FN(jksengine_bind_helper);

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
 * File: JKSEngine DSA Implementation
 *
 * Notes:
 * At the moment it is not possible to generate keys with this engine.
 * In future versions of OPENSSL, it can be possible to get a key identifier as input
 * that can be passed to the engine. Then the function jksengine_dsa_keygen can be included
 * to the DSA_METHOD.
 *
 * There is probably a Bug in OPENSSL 0.9.8o. During PKCS7 object creation in pk7_doit.c
 * (function PKCS7_dataFinal, line 752-759) pointer to digest methods of the engine get overwritten
 * by standard function pointer. Therefore, engine does not work properly anymore. In OPENSSL
 * 1.0.0d this faulty part of the mentioned function is not there anymore.
 */

#include "JKSEngine.h"


int jksengine_dsa_init(DSA *dsa){
	DEBUG("FUNCTION_CALL: jksengine_dsa_init\n");

	return 1;
}

int jksengine_dsa_finish(DSA *dsa){
	DEBUG("FUNCTION_CALL: jksengine_dsa_finish\n");

	return 1;
}

int jksengine_dsa_bind(){
	const DSA_METHOD *dsa_m = NULL;


	DEBUG("FUNCTION_CALL: jksengine_dsa_bind\n");

	dsa_m = DSA_OpenSSL();
	if (!dsa_m){
		ERR("ERROR: No Pointer to OpenSSL DSA Functions\n");
		return 1;
	}
	jksengine_dsa_methods.dsa_do_verify = dsa_m->dsa_do_verify;
	jksengine_dsa_methods.bn_mod_exp = dsa_m->bn_mod_exp;
	jksengine_dsa_methods.dsa_mod_exp = dsa_m->dsa_mod_exp;

	return 0;
}


DSA_SIG *jksengine_dsa_sign(const unsigned char *dgst, int dlen, DSA *dsa){
	DSA_SIG *sig = NULL;
	char *data = NULL;
	const unsigned char *p = NULL;
	unsigned int datalen;


	DEBUG("FUNCTION_CALL: jksengine_dsa_sign\n");

	sig = DSA_SIG_new();
	data = processData(dsa->engine,PD_SIGN,dlen,dgst,NULL, &datalen,ID_DSA);
	if (!data){
		ERR("ERROR: Data Processing Failed\n");
		return NULL;
	}

	p = (const unsigned char *)data;

	sig = d2i_DSA_SIG(&sig, &p, datalen);
	if (!sig){
		ERR("Converting Signature Failed\n");
		return NULL;
	}

	// Free Memory
	OPENSSL_free(data);
	data = NULL;
	p = NULL;

	return sig;
}

int jksengine_dsa_keygen(DSA *dsa,int bits,BIGNUM *e,BN_GENCB *cb){
	DEBUG("FUNCTION_CALL: jksengine_dsa_keygen\n");

	if (processData(dsa->engine,PD_GENKEY,0,NULL,NULL,NULL,ID_DSA)){
		ERR("ERROR: Generating Key failed\n");
		return 1;
	}

	return 0;
}


DSA_METHOD jksengine_dsa_methods = {
		"Implemented JKSEngine DSA Methods",
		jksengine_dsa_sign,
		NULL, // dsa_sign_setup
		NULL, //dsa_verify -> OpenSSL
		NULL, //mod_exp -> OpenSSL
		NULL, //bn_mod_exp -> OpenSSL
		jksengine_dsa_init,
		jksengine_dsa_finish,
		0,
		NULL, //app_data
		NULL, //param_gen
		NULL, //jksengine_dsa_keygen
} ;

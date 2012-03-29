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
 * File: JKSEngine ECDSA Implementation
 *
 * Notes:
 * There is probably a Bug in OPENSSL 0.9.8o. During PKCS7 object creation in pk7_doit.c
 * (function PKCS7_dataFinal, line 752-759) pointer to digest methods of the engine get overwritten
 * by standard function pointer. Therefore, engine does not work properly anymore. In OPENSSL
 * 1.0.0d this faulty part of the mentioned function is not there anymore.
 *
 * Function jksengine_ecdsa_sign does not work properly at the moment. Engine Context is needed but
 * there is no reference to the engine within the function. Probably it can change in newer versions
 * of OPENSSL.
 *
 * ECDSA_METHOD definition was copied to JKSEngine.h because it is not available through normal OPENSSL includes.
 * If it changes in newer versions of OPENSSL then the definition should be removed from the header file.
 */

#include "JKSEngine.h"



int jksengine_ecdsa_bind(){
	const struct ecdsa_method *ecdsa_m = NULL;


	DEBUG("FUNCTION_CALL: jksengine_ecdsa_bind\n");

	ecdsa_m = ECDSA_OpenSSL();
	if (!ecdsa_m){
		ERR("ERROR: No Pointer to OpenSSL ECDSA Functions\n");
		return 1;
	}
	jksengine_ecdsa_methods.ecdsa_do_verify = ecdsa_m->ecdsa_do_verify;

	return 0;
}

ECDSA_SIG *jksengine_ecdsa_sign(const unsigned char *dgst, int dlen, const BIGNUM *inv, const BIGNUM *rp, EC_KEY *eckey){
	ECDSA_SIG *sig = NULL;
	char *data = NULL;
	const unsigned char *p = NULL;
	unsigned int datalen;


	DEBUG("FUNCTION_CALL: jksengine_ecdsa_sign\n");

	sig = ECDSA_SIG_new();
	if (!sig){
		ERR("ERROR: Creation of ECDSA_SIG Structure failed\n");
		return NULL;
	}

	// Does not work, because the first parameter has to be the Engine, but the Engine is not available in this function
	data = processData(NULL,PD_SIGN,dlen,dgst,NULL, &datalen,ID_ECDSA);

	if (!data){
		ERR("ERROR: Signing Data failed\n");
		return NULL;
	}

	p = (const unsigned char *)data;

	sig = d2i_ECDSA_SIG(&sig, &p, datalen);
	if (!sig){
		ERR("ERROR: Converting Signature failed\n");
		return NULL;
	}

	// Free Memory
	OPENSSL_free(data);
	data = NULL;
	p = NULL;

	return sig;
}


struct ecdsa_method jksengine_ecdsa_methods = {
		"Implemented JKSEngine ECDSA Methods",
		NULL, // jksengine_dsa_ecdsa_sign
		NULL, // dsa_sign_setup
		NULL, //dsa_verify -> OpenSSL
		0,
		NULL, //app_data
} ;


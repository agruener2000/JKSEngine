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
 * File: JKSEngine RSA Implementation
 *
 * Notes:
 * At the moment it is not possible to generate Keys with this engine.
 * In future versions of OPENSSL, it can be possible to get an input from a key identifier
 * that can be passed to the engine. Then the function jksengine_rsa_keygen can be included
 * to the RSA_METHOD.
 */

#include "JKSEngine.h"

int jksengine_rsa_bind(){
	const RSA_METHOD *rsa_m = NULL;


	DEBUG("FUNCTION_CALL: jksengine_rsa_bind\n");

	rsa_m = RSA_PKCS1_SSLeay();
	if (!rsa_m){
		ERR("ERROR: No Pointer to OpenSSL RSA Functions");
		return 1;
	}
	jksengine_rsa_methods.rsa_pub_dec = rsa_m->rsa_pub_dec;
	jksengine_rsa_methods.rsa_pub_enc = rsa_m->rsa_pub_enc;
	jksengine_rsa_methods.bn_mod_exp = rsa_m->bn_mod_exp;
	jksengine_rsa_methods.rsa_mod_exp = rsa_m->rsa_mod_exp;
	jksengine_rsa_methods.rsa_verify = rsa_m->rsa_verify;
	return 0;
}


int jksengine_rsa_init(RSA *rsa){
	DEBUG("FUNCTION_CALL: jksengine_rsa_init\n");

	return 1;
}

int jksengine_rsa_finish(RSA *rsa){
	DEBUG("FUNCTION_CALL: jksengine_rsa_finish\n");

	return 1;
}

int jksengine_rsa_priv_enc(int flen,const unsigned char *from, unsigned char *to, RSA *rsa,int padding){
	DEBUG("FUNCTION_CALL: jksengine_rsa_priv_enc\n");

	// Function is used as Signature Function by old OpenSSL Applications
	if ((processData(rsa->engine,PD_SIGN,flen,from,to,0,ID_RSA))||(!to)){
		ERR("ERROR: Signing Data failed\n");
		return 0;
	}

	return 1;
}

int jksengine_rsa_priv_dec(int flen, const unsigned char *from,unsigned char *to, RSA *rsa,int padding){
	unsigned int tolen = 0;


	DEBUG("FUNCTION_CALL: jksengine_rsa_priv_dec\n");

	if ((processData(rsa->engine,PD_DECRYPT,flen,from,to,&tolen,ID_RSA))||(!to)){
		ERR("ERROR: Decryption failed\n");
		return 0;
	}

	return tolen;
}

int jksengine_rsa_sign(int dtype, const unsigned char *m, unsigned int m_length, unsigned char *sigret, unsigned int *siglen, const RSA *rsa){
	DEBUG("FUNCTION_CALL: jksengine_rsa_sign\n");

	if ((processData(rsa->engine,PD_SIGN,m_length,m,sigret,siglen,ID_RSA))||(!siglen)||(!sigret)){
		ERR("ERROR: Signing Data failed\n");
		return 0;
	}

	return 1;
}

int jksengine_rsa_keygen(RSA *rsa,int bits,BIGNUM *e,BN_GENCB *cb){
	DEBUG("FUNCTION_CALL: jksengine_rsa_keygen\n");


	if (processData(rsa->engine,PD_GENKEY,0,NULL,NULL,NULL,ID_RSA)){
		ERR("ERROR: Generating Key failed\n");
		return 1;
	}

	return 1;
}


RSA_METHOD jksengine_rsa_methods = {
		"Implemented JKSEngine RSA Methods",
		NULL, //pub_enc -> OpenSSL
		NULL, //pub_dec -> OpenSSL
		jksengine_rsa_priv_enc,
		jksengine_rsa_priv_dec,
		NULL, //mod_exp,
		NULL, //bn_mod_exp,
		jksengine_rsa_init,
		jksengine_rsa_finish,
		(RSA_FLAG_SIGN_VER | RSA_FLAG_EXT_PKEY | RSA_METHOD_FLAG_NO_CHECK),
		NULL, //app_data
		jksengine_rsa_sign,
		NULL, // verify -> OpenSSL
		NULL, //jksengine_rsa_keygen
} ;


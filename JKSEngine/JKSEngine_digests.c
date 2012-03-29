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
 * File: JKSEngine Digests Implementations
 */

#include <string.h>
#include <openssl/engine.h>
#include <openssl/md5.h>
#include <openssl/ripemd.h>

#include "JKSEngine.h"



int jksengine_digests_init(EVP_MD_CTX *ctx,int dig_id){
	JKSENGINE_MD_CTX *jks_md_ctx = NULL;


	DEBUG("FUNCTION_CALL: jksengine_digests_init\n");

	if (!(ctx->md_data)){
		ctx->md_data = OPENSSL_malloc(sizeof(JKSENGINE_MD_CTX));
		if (!(ctx->md_data)){
			ERR("ERROR: Memory Allocation Failed\n");
			return 0;
		}

		jks_md_ctx = (JKSENGINE_MD_CTX *)(ctx->md_data);
		if (!(ctx->md_data)){
			ERR("ERROR: No Context MD Data\n");
			return 0;
		}

		switch (dig_id){
			case NID_dsa:
			case NID_sha1:
				jks_md_ctx->md_data = OPENSSL_malloc(sizeof(SHA_CTX));
				break;
			case NID_sha224:
				jks_md_ctx->md_data = OPENSSL_malloc(sizeof(SHA256_CTX));
				break;
			case NID_sha256:
				jks_md_ctx->md_data = OPENSSL_malloc(sizeof(SHA256_CTX));
				break;
			case NID_sha384:
				jks_md_ctx->md_data = OPENSSL_malloc(sizeof(SHA512_CTX));
				break;
			case NID_sha512:
				jks_md_ctx->md_data = OPENSSL_malloc(sizeof(SHA512_CTX));
				break;
			case NID_md5:
				jks_md_ctx->md_data = OPENSSL_malloc(sizeof(MD5_CTX));
				break;
			case NID_ripemd160:
				jks_md_ctx->md_data = OPENSSL_malloc(sizeof(RIPEMD160_CTX));
				break;
			default:
				//error;
				break;
		}

		if (!(jks_md_ctx->md_data)){
			ERR("ERROR: Memory Allocation Failed\n");
			return 0;
		}

		jks_md_ctx->datalen = 0;
		jks_md_ctx->notcleaned = 1;
	}

	switch (dig_id){
		case NID_dsa:
		case NID_sha1:
			SHA1_Init(jks_md_ctx->md_data);
			break;
		case NID_sha224:
			SHA224_Init(jks_md_ctx->md_data);
			break;
		case NID_sha256:
			SHA256_Init(jks_md_ctx->md_data);
			break;
		case NID_sha384:
			SHA384_Init(jks_md_ctx->md_data);
			break;
		case NID_sha512:
			SHA512_Init(jks_md_ctx->md_data);
			break;
		case NID_md5:
			MD5_Init(jks_md_ctx->md_data);
			break;
		case NID_ripemd160:
			RIPEMD160_Init(jks_md_ctx->md_data);
			break;
		default:
			//error;
			break;
	}

	return 1;
}


int jksengine_digests_update(EVP_MD_CTX *ctx,const void *data,unsigned long count, int dig_id){
	char *olddata = NULL;
	char *beginnew = NULL;
	int i = 0;
	JKSENGINE_MD_CTX *jks_md_ctx = NULL;


	DEBUG("FUNCTION_CALL: jksengine_digests_update\n");

	if (!ctx){
		ERR("ERROR: NULL Pointer to EVP_MD_CTX\n");
		return 0;
	}

	jks_md_ctx = (JKSENGINE_MD_CTX *)(ctx->md_data);
	if (!jks_md_ctx){
		ERR("ERROR: NULL Pointer to CTX->md_data\n");
		return 0;
	}

	// Save old Data only if old Data exists
	if (jks_md_ctx->datalen){
		olddata = OPENSSL_malloc((jks_md_ctx->datalen)*sizeof(char));
		if (!olddata){
			ERR("ERROR: Memory Allocation Failed\n");
			return 0;
		}

		memcpy(olddata,jks_md_ctx->data,jks_md_ctx->datalen);
		OPENSSL_free(jks_md_ctx->data);

		jks_md_ctx->data = OPENSSL_malloc(((jks_md_ctx->datalen)+count)*sizeof(char));
		if (!(jks_md_ctx->data)){
			ERR("ERROR: Memory Allocation Failed\n");
			return 0;
		}

		memcpy(jks_md_ctx->data,olddata,jks_md_ctx->datalen);
		beginnew = jks_md_ctx->data;
		if (!beginnew){
			ERR("ERROR: NULL Pointer\n");
			return 0;
		}

		for (i=0;i<jks_md_ctx->datalen;i++){
			beginnew++;
		}

		memcpy(beginnew,data,count);
		jks_md_ctx->datalen += count;
		OPENSSL_free(olddata);
		olddata = NULL;
	} else {
		jks_md_ctx->datalen = count;

		jks_md_ctx->data = OPENSSL_malloc((count)*sizeof(char));
		if (!(jks_md_ctx->data)){
			ERR("ERROR: Memory Allocation Failed\n");
			return 0;
		}

		memcpy(jks_md_ctx->data,data,count);
	}

	switch (dig_id){
		case NID_dsa:
		case NID_sha1:
			SHA1_Update(jks_md_ctx->md_data,data,count);
			break;
		case NID_sha224:
			SHA224_Update(jks_md_ctx->md_data,data,count);
			break;
		case NID_sha256:
			SHA256_Update(jks_md_ctx->md_data,data,count);
			break;
		case NID_sha384:
			SHA384_Update(jks_md_ctx->md_data,data,count);
			break;
		case NID_sha512:
			SHA512_Update(jks_md_ctx->md_data,data,count);
			break;
		case NID_md5:
			MD5_Update(jks_md_ctx->md_data,data,count);
			break;
		case NID_ripemd160:
			RIPEMD160_Update(jks_md_ctx->md_data,data,count);
			break;
		default:
			//error;
			break;
	}

	return 1;
}


int jksengine_digests_final(EVP_MD_CTX *ctx,unsigned char *md, int dig_id){
	JKSENGINE_MD_CTX *jks_md_ctx = NULL;
	JKSENGINE_CTX *jks_ctx = NULL;
	JKSENGINE_MD_GEN_CTX *jks_md_gen_ctx = NULL;


	DEBUG("FUNCTION_CALL: jksengine_digests_final\n");

	if (!ctx){
		ERR("ERROR: NULL Pointer EVP_MD_CTX\n");
		return 0;
	}

	jks_ctx = ENGINE_get_ex_data(ctx->engine,jksengine_ctx_index);
	jks_md_ctx = (JKSENGINE_MD_CTX*)(ctx->md_data);
	if ((!jks_ctx) || (!jks_md_ctx)){
			ERR("ERROR: Null Pointer to Context Information\n");
			return 0;
		}

	// Iterate to the last saved Hash
	if (!jks_ctx->hash){
		jks_ctx->hash = OPENSSL_malloc(sizeof(JKSENGINE_MD_GEN_CTX));
		jks_md_gen_ctx = jks_ctx->hash;
		jks_md_gen_ctx->next = NULL;
	} else {
		jks_md_gen_ctx = jks_ctx->hash;

		while ((jks_md_gen_ctx->next!=NULL)){
			jks_md_gen_ctx = jks_md_gen_ctx->next;
		}

		jks_md_gen_ctx->next = OPENSSL_malloc(sizeof(JKSENGINE_MD_GEN_CTX));
		if (!jks_md_gen_ctx){
			ERR("ERROR: Null Pointer to Context Information\n");
			return 0;
		}
		jks_md_gen_ctx = jks_md_gen_ctx->next;
		jks_md_gen_ctx->next = NULL;
	}

	jks_md_gen_ctx->data = OPENSSL_malloc((jks_md_ctx->datalen)*sizeof(char));
	if (!(jks_md_gen_ctx->data)){
		ERR("ERROR: Memory Allocation Failed\n");
		return 0;
	}


	memcpy(jks_md_gen_ctx->data,jks_md_ctx->data,jks_md_ctx->datalen);

	jks_md_gen_ctx->datalen = jks_md_ctx->datalen;

	switch (dig_id){
		case NID_dsa:
			jks_md_gen_ctx->hash_id = BUF_strdup(ID_SHA1);
			jks_md_gen_ctx->md_data = OPENSSL_malloc(20*sizeof(char));
			SHA1_Final(md,jks_md_ctx->md_data);
			break;
		case NID_sha1:
			jks_md_gen_ctx->hash_id = BUF_strdup(ID_SHA1);
			jks_md_gen_ctx->md_data = OPENSSL_malloc(20*sizeof(char));
			SHA1_Final(md,jks_md_ctx->md_data);
			break;
		case NID_sha224:
			jks_md_gen_ctx->hash_id = BUF_strdup(ID_SHA224);
			jks_md_gen_ctx->md_data = OPENSSL_malloc(28*sizeof(char));
			SHA224_Final(md,jks_md_ctx->md_data);
			break;
		case NID_sha256:
			jks_md_gen_ctx->hash_id = BUF_strdup(ID_SHA256);
			jks_md_gen_ctx->md_data = OPENSSL_malloc(32*sizeof(char));
			SHA256_Final(md,jks_md_ctx->md_data);
			break;
		case NID_sha384:
			jks_md_gen_ctx->hash_id = BUF_strdup(ID_SHA384);
			jks_md_gen_ctx->md_data = OPENSSL_malloc(48*sizeof(char));
			SHA384_Final(md,jks_md_ctx->md_data);
			break;
		case NID_sha512:
			jks_md_gen_ctx->hash_id = BUF_strdup(ID_SHA512);
			jks_md_gen_ctx->md_data = OPENSSL_malloc(64*sizeof(char));
			SHA512_Final(md,jks_md_ctx->md_data);
			break;
		case NID_md5:
			jks_md_gen_ctx->hash_id = BUF_strdup(ID_MD5);
			jks_md_gen_ctx->md_data = OPENSSL_malloc(16*sizeof(char));
			MD5_Final(md,jks_md_ctx->md_data);
			break;
		case NID_ripemd160:
			jks_md_gen_ctx->hash_id = BUF_strdup(ID_RIPEMD160);
			jks_md_gen_ctx->md_data = OPENSSL_malloc(20*sizeof(char));
			RIPEMD160_Final(md,jks_md_ctx->md_data);
			break;
		default:
			//error;
			break;
	}

	if (!(jks_md_gen_ctx->md_data)){
			ERR("ERROR: Memory Allocation Failed\n");
			return 0;
		}

	switch (dig_id){
		case NID_dsa:
			memcpy(jks_md_gen_ctx->md_data,md,20);
			break;
		case NID_sha1:
			memcpy(jks_md_gen_ctx->md_data,md,20);
			break;
		case NID_sha224:
			memcpy(jks_md_gen_ctx->md_data,md,28);
			break;
		case NID_sha256:
			memcpy(jks_md_gen_ctx->md_data,md,32);
			break;
		case NID_sha384:
			memcpy(jks_md_gen_ctx->md_data,md,48);
			break;
		case NID_sha512:
			memcpy(jks_md_gen_ctx->md_data,md,64);
			break;
		case NID_md5:
			memcpy(jks_md_gen_ctx->md_data,md,16);
			break;
		case NID_ripemd160:
			memcpy(jks_md_gen_ctx->md_data,md,20);
			break;
		default:
			//error;
			break;
		}

	return 1;
}


int jksengine_digests_cleanup(EVP_MD_CTX *ctx){
	JKSENGINE_MD_CTX *jks_md_ctx = NULL;


	DEBUG("FUNCTION_CALL: jksengine_digests_cleanup\n");

	if (!ctx){
		return 1;
	}

	if (ctx->md_data){
		jks_md_ctx = (JKSENGINE_MD_CTX *)(ctx->md_data);
	}

	if ((jks_md_ctx) && (jks_md_ctx->notcleaned==1)){
		if (jks_md_ctx->data){
			memset(jks_md_ctx->data,0,jks_md_ctx->datalen);
			if (jks_md_ctx->datalen>0){
				OPENSSL_free(jks_md_ctx->data);
			}
			jks_md_ctx->data = NULL;
		}

		jks_md_ctx->datalen=0;

		if (jks_md_ctx->md_data){
			OPENSSL_free(jks_md_ctx->md_data);
			jks_md_ctx->md_data = NULL;
		}

		jks_md_ctx->notcleaned = 0;
		OPENSSL_free(ctx->md_data);
		ctx->md_data = NULL;
		jks_md_ctx = NULL;

	}

	return 1;
}


int jksengine_sha1_init(EVP_MD_CTX *ctx){
	DEBUG("FUNCTION_CALL: jksengine_sha1_init\n");

	return (jksengine_digests_init(ctx,NID_sha1));
}

int jksengine_sha1_update(EVP_MD_CTX *ctx,const void *data,unsigned long count){
	DEBUG("FUNCTION_CALL: jksengine_sha1_update\n");

	return (jksengine_digests_update(ctx, data, count, NID_sha1));
}

int jksengine_sha1_final(EVP_MD_CTX *ctx,unsigned char *md){
	DEBUG("FUNCTION_CALL: jksengine_sha1_final\n");

	return (jksengine_digests_final(ctx, md, NID_sha1));
}

int jksengine_md5_init(EVP_MD_CTX *ctx){
	DEBUG("FUNCTION_CALL: jksengine_md5_init\n");

	return (jksengine_digests_init(ctx,NID_md5));
}

int jksengine_md5_update(EVP_MD_CTX *ctx,const void *data,unsigned long count){
	DEBUG("FUNCTION_CALL: jksengine_md5_update\n");

	return (jksengine_digests_update(ctx, data, count, NID_md5));
}

int jksengine_md5_final(EVP_MD_CTX *ctx,unsigned char *md){
	DEBUG("FUNCTION_CALL: jksengine_md5_final\n");

	return (jksengine_digests_final(ctx, md, NID_md5));
}

int jksengine_sha224_init(EVP_MD_CTX *ctx){
	DEBUG("FUNCTION_CALL: jksengine_sha224_init\n");

	return (jksengine_digests_init(ctx,NID_sha224));
}

int jksengine_sha224_update(EVP_MD_CTX *ctx,const void *data,unsigned long count){
	DEBUG("FUNCTION_CALL: jksengine_sha224_update\n");

	return (jksengine_digests_update(ctx, data, count, NID_sha224));
}

int jksengine_sha224_final(EVP_MD_CTX *ctx,unsigned char *md){
	DEBUG("FUNCTION_CALL: jksengine_sha224_final\n");

	return (jksengine_digests_final(ctx, md, NID_sha224));
}

int jksengine_sha256_init(EVP_MD_CTX *ctx){
	DEBUG("FUNCTION_CALL: jksengine_sha256_init\n");

	return (jksengine_digests_init(ctx,NID_sha256));
}

int jksengine_sha256_update(EVP_MD_CTX *ctx,const void *data,unsigned long count){
	DEBUG("FUNCTION_CALL: jksengine_sha256_update\n");

	return (jksengine_digests_update(ctx, data, count, NID_sha256));
}

int jksengine_sha256_final(EVP_MD_CTX *ctx,unsigned char *md){
	DEBUG("FUNCTION_CALL: jksengine_sha256_final\n");

	return (jksengine_digests_final(ctx, md, NID_sha256));
}

int jksengine_sha384_init(EVP_MD_CTX *ctx){
	DEBUG("FUNCTION_CALL: jksengine_sha384_init\n");

	return (jksengine_digests_init(ctx,NID_sha384));
}

int jksengine_sha384_update(EVP_MD_CTX *ctx,const void *data,unsigned long count){
	DEBUG("FUNCTION_CALL: jksengine_sha384_update\n");

	return (jksengine_digests_update(ctx, data, count, NID_sha384));
}

int jksengine_sha384_final(EVP_MD_CTX *ctx,unsigned char *md){
	DEBUG("FUNCTION_CALL: jksengine_sha384_final\n");

	return (jksengine_digests_final(ctx, md, NID_sha384));
}

int jksengine_sha512_init(EVP_MD_CTX *ctx){
	DEBUG("FUNCTION_CALL: jksengine_sha512_init\n");

	return (jksengine_digests_init(ctx,NID_sha512));
}

int jksengine_sha512_update(EVP_MD_CTX *ctx,const void *data,unsigned long count){
	DEBUG("FUNCTION_CALL: jksengine_sha512_update\n");

	return (jksengine_digests_update(ctx, data, count, NID_sha512));
}

int jksengine_sha512_final(EVP_MD_CTX *ctx,unsigned char *md){
	DEBUG("FUNCTION_CALL: jksengine_sha512_final\n");

	return (jksengine_digests_final(ctx, md, NID_sha512));
}

int jksengine_ripemd160_init(EVP_MD_CTX *ctx){
	DEBUG("FUNCTION_CALL: jksengine_ripemd160_init\n");

	return (jksengine_digests_init(ctx,NID_ripemd160));
}

int jksengine_ripemd160_update(EVP_MD_CTX *ctx,const void *data,unsigned long count){
	DEBUG("FUNCTION_CALL: jksengine_ripemd160_update\n");

	return (jksengine_digests_update(ctx, data, count, NID_ripemd160));
}

int jksengine_ripemd160_final(EVP_MD_CTX *ctx,unsigned char *md){
	DEBUG("FUNCTION_CALL: jksengine_ripemd160_final\n");

	return (jksengine_digests_final(ctx, md, NID_ripemd160));
}

int jksengine_mddsa_init(EVP_MD_CTX *ctx){
	DEBUG("FUNCTION_CALL: jksengine_mddsa_init\n");

	return (jksengine_digests_init(ctx,NID_dsa));
}

int jksengine_mddsa_update(EVP_MD_CTX *ctx,const void *data,unsigned long count){
	DEBUG("FUNCTION_CALL: jksengine_mddsa_update\n");

	return (jksengine_digests_update(ctx, data, count, NID_dsa));
}

int jksengine_mddsa_final(EVP_MD_CTX *ctx,unsigned char *md){
	DEBUG("FUNCTION_CALL: jksengine_mddsa_final\n");

	return (jksengine_digests_final(ctx, md, NID_dsa));
}

const EVP_MD digest_sha1 =
	{
	NID_sha1,
	(NID_sha1WithRSAEncryption||NID_dsaWithSHA1),
	20,
	0,
	jksengine_sha1_init,
	jksengine_sha1_update,
	jksengine_sha1_final,
	NULL,
	jksengine_digests_cleanup,
	EVP_PKEY_RSA_method,
	sizeof(JKSENGINE_MD_CTX)
	};

const EVP_MD digest_md5 =
	{
	NID_md5,
	NID_md5WithRSAEncryption,
	16,
	0,
	jksengine_md5_init,
	jksengine_md5_update,
	jksengine_md5_final,
	NULL,
	jksengine_digests_cleanup,
	EVP_PKEY_RSA_method,
	sizeof(JKSENGINE_MD_CTX)
	};

const EVP_MD digest_sha224 =
	{
	NID_sha224,
	NID_sha224WithRSAEncryption,
	28,
	0,
	jksengine_sha224_init,
	jksengine_sha224_update,
	jksengine_sha224_final,
	NULL,
	jksengine_digests_cleanup,
	EVP_PKEY_RSA_method,
	sizeof(JKSENGINE_MD_CTX)
	};

const EVP_MD digest_sha256 =
	{
	NID_sha256,
	NID_sha256WithRSAEncryption,
	32,
	0,
	jksengine_sha256_init,
	jksengine_sha256_update,
	jksengine_sha256_final,
	NULL,
	jksengine_digests_cleanup,
	EVP_PKEY_RSA_method,
	sizeof(JKSENGINE_MD_CTX)
	};

const EVP_MD digest_sha384 =
	{
	NID_sha384,
	NID_sha384WithRSAEncryption,
	48,
	0,
	jksengine_sha384_init,
	jksengine_sha384_update,
	jksengine_sha384_final,
	NULL,
	jksengine_digests_cleanup,
	EVP_PKEY_RSA_method,
	sizeof(JKSENGINE_MD_CTX)
	};

const EVP_MD digest_sha512 =
	{
	NID_sha512,
	NID_sha512WithRSAEncryption,
	64,
	0,
	jksengine_sha512_init,
	jksengine_sha512_update,
	jksengine_sha512_final,
	NULL,
	jksengine_digests_cleanup,
	EVP_PKEY_RSA_method,
	sizeof(JKSENGINE_MD_CTX)
	};

const EVP_MD digest_ripemd160 =
	{
	NID_ripemd160,
	NID_ripemd160WithRSA,
	20,
	0,
	jksengine_ripemd160_init,
	jksengine_ripemd160_update,
	jksengine_ripemd160_final,
	NULL,
	jksengine_digests_cleanup,
	EVP_PKEY_RSA_method,
	sizeof(JKSENGINE_MD_CTX)
	};

const EVP_MD digest_mddsa =
	{
	NID_dsa,
	NID_dsaWithSHA1,
	20,
	0,
	jksengine_mddsa_init,
	jksengine_mddsa_update,
	jksengine_mddsa_final,
	NULL,
	jksengine_digests_cleanup,
	EVP_PKEY_DSA_method,
	sizeof(JKSENGINE_MD_CTX)
	};

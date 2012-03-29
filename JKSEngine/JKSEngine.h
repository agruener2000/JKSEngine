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
 * File:Header File of JKSENGINE
 */

#ifndef JKSENGINE_H_
#define JKSENGINE_H_

#include <openssl/engine.h>

/*
 * DEBUG Definitions
 */
//#define DEBUGMODE
#define BUG_ECDSA

#ifdef DEBUGMODE// DEBUG Mode
#define DEBUG(Msg)	fprintf(stderr,Msg)
#else // NORMAL RUN Mode
#define DEBUG(Msg)
#endif

#define ERR(Msg) fprintf(stderr,Msg);

/*
 * Key Parameter Structures
 */
struct PARAMPAIR_STRUCT{
	char *key;
	char *value;
	struct PARAMPAIR_STRUCT *next;
};

typedef struct PARAMPAIR_STRUCT PARAMPAIR;

struct KEY_ID_STRUCT{
	char *keystore;
	PARAMPAIR *params;
};

typedef struct KEY_ID_STRUCT KEY_ID;

struct JKSENGINE_MD_GEN_CTX_STRUCT{
	char *data;
	int datalen;
	void *md_data;
	char *hash_id;
	struct JKSENGINE_MD_GEN_CTX_STRUCT *next;
};
typedef struct JKSENGINE_MD_GEN_CTX_STRUCT JKSENGINE_MD_GEN_CTX;

/*
 * ECDSA Method Structure is not in an include header file. This is a Bug. It can change
 * in newer OpenSSL versions.If it changes then delete this definition.
 */

#ifdef BUG_ECDSA

struct ecdsa_method
	{
	const char *name;
	ECDSA_SIG *(*ecdsa_do_sign)(const unsigned char *dgst, int dgst_len,
			const BIGNUM *inv, const BIGNUM *rp, EC_KEY *eckey);
	int (*ecdsa_sign_setup)(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv,
			BIGNUM **r);
	int (*ecdsa_do_verify)(const unsigned char *dgst, int dgst_len,
			const ECDSA_SIG *sig, EC_KEY *eckey);
	int flags;
	char *app_data;
	};

#endif

/*
 * Function Prototypes
 */
void ENGINE_load_jksengine(void);

int jksengine_init(ENGINE *);
EVP_PKEY* jksengine_load_key(ENGINE *, const char *, UI_METHOD *, void *);
EVP_PKEY* jksengine_load_pubkey(ENGINE *, const char *, UI_METHOD *, void *);
int jksengine_ctrl(ENGINE *,int, long, void *, void (*)(void));
int jksengine_destroy(ENGINE *);
int jksengine_register_digests(ENGINE *, const EVP_MD **, const int **, int);
int jksengine_bind(ENGINE * );
ENGINE *engine_jksengine(void);
void ENGINE_load_jksengine(void);
int jksengine_bind_helper(ENGINE *, const char *);

extern char *processData(ENGINE *,char *, int, const unsigned char *, const unsigned char *, unsigned int *, char *);
extern int byteArraytoInt(char *);
extern EVP_PKEY *getPublicKey(ENGINE *e);
extern KEY_ID *parseKeyIdentifier(const char *);
extern char *getConnToolName(char *);
extern char *getConnToolPath(char *);
extern char *getAlgorithmID(char *,char *);
extern void KEY_ID_free(KEY_ID *);
extern void JKSENGINE_MD_GEN_CTX_free(JKSENGINE_MD_GEN_CTX *);

extern int jksengine_digests_cleanup(EVP_MD_CTX *);
extern int jksengine_digest_nids[];

extern int jksengine_sha1_init(EVP_MD_CTX *);
extern int jksengine_sha1_update(EVP_MD_CTX *,const void *,unsigned long);
extern int jksengine_sha1_final(EVP_MD_CTX *,unsigned char *);
extern const EVP_MD digest_sha1;

extern int jksengine_md5_init(EVP_MD_CTX *);
extern int jksengine_md5_update(EVP_MD_CTX *,const void *,unsigned long);
extern int jksengine_md5_final(EVP_MD_CTX *,unsigned char *);
extern int jksengine_md5_cleanup(EVP_MD_CTX *);
extern const EVP_MD digest_md5;

extern int jksengine_sha224_init(EVP_MD_CTX *);
extern int jksengine_sha224_update(EVP_MD_CTX *,const void *,unsigned long);
extern int jksengine_sha224_final(EVP_MD_CTX *,unsigned char *);
extern const EVP_MD digest_sha224;

extern int jksengine_sha256_init(EVP_MD_CTX *);
extern int jksengine_sha256_update(EVP_MD_CTX *,const void *,unsigned long);
extern int jksengine_sha256_final(EVP_MD_CTX *,unsigned char *);
extern const EVP_MD digest_sha256;

extern int jksengine_sha384_init(EVP_MD_CTX *);
extern int jksengine_sha384_update(EVP_MD_CTX *,const void *,unsigned long);
extern int jksengine_sha384_final(EVP_MD_CTX *,unsigned char *);
extern const EVP_MD digest_sha384;

extern int jksengine_sha512_init(EVP_MD_CTX *);
extern int jksengine_sha512_update(EVP_MD_CTX *,const void *,unsigned long);
extern int jksengine_sha512_final(EVP_MD_CTX *,unsigned char *);
extern const EVP_MD digest_sha512;

extern int jksengine_ripemd160_init(EVP_MD_CTX *);
extern int jksengine_ripemd160_update(EVP_MD_CTX *,const void *,unsigned long);
extern int jksengine_ripemd160_final(EVP_MD_CTX *,unsigned char *);
extern const EVP_MD digest_ripemd160;

extern int jksengine_mddsa_init(EVP_MD_CTX *);
extern int jksengine_mddsa_update(EVP_MD_CTX *,const void *,unsigned long);
extern int jksengine_mddsa_final(EVP_MD_CTX *,unsigned char *);
extern const EVP_MD digest_mddsa;

extern int jksengine_rsa_init(RSA *);
extern int jksengine_rsa_finish(RSA *);
extern int jksengine_rsa_priv_dec(int, const unsigned char *,unsigned char *, RSA *,int);
extern int jksengine_rsa_sign(int, const unsigned char *, unsigned int, unsigned char *, unsigned int *, const RSA *);
extern int jksengine_rsa_priv_enc(int,const unsigned char *, unsigned char *, RSA *,int);
extern int jksengine_rsa_bind(void);
extern RSA_METHOD jksengine_rsa_methods;

extern int jksengine_dsa_init(DSA *);
extern int jksengine_dsa_finish(DSA *);
DSA_SIG *jksengine_dsa_sign(const unsigned char *dgst, int dlen, DSA *dsa);
extern int jksengine_dsa_bind(void);
extern DSA_METHOD jksengine_dsa_methods;

extern int jksengine_ecdsa_bind();
extern ECDSA_SIG *jksengine_ecdsa_sign(const unsigned char *, int, const BIGNUM *, const BIGNUM *, EC_KEY *);
extern ECDSA_METHOD jksengine_ecdsa_methods;


/*
 * Context Area Index
 */
extern int jksengine_ctx_index;


/*
 * Context Area Structures
 */
struct JKSENGINE_MD_CTX_STRUCT{
	char *data;
	int datalen;
	void *md_data;
	int notcleaned;
};
typedef struct JKSENGINE_MD_CTX_STRUCT JKSENGINE_MD_CTX;

struct JKSENGINE_CTX_STRUCT{
	char *keystoreprovider;
	char *connectorpath;
	char *keystorepass;
	char *privkeystore;
	char *privkeyalias;
	char *java;
	JKSENGINE_MD_GEN_CTX *hash;
};
typedef struct JKSENGINE_CTX_STRUCT JKSENGINE_CTX;


/*
 * Callback Password Structure
 */
struct pw_data_struct{
	const void *password;
	const char *prompt_info;
};
typedef struct pw_data_struct PW_DATA;


// JKSEngine ID
#define ID_JKSENGINE "JKSEngine"


// Standard Configuration Values
#define STDCONNPATH	"/usr/sbin/ConnJKSEngine.jar"
#define STDKSPROVIDER	"nCipherKM"
#define STDJAVA		"/usr/bin/java"
#define STDPASS		"123456"

// JKSEngine Config Commands
#define CMDKEYSTOREPASS	2
#define CMDCONNECTORPATH	3
#define CMDKEYSTOREPROVIDER 4
#define CMDJAVA			5


// JKSEngine Communication Pipes
#define ENGINE_READ		readpipe[0]
#define ENGINE_WRITE	writepipe[1]
#define JAVACONN_READ	writepipe[0]
#define JAVACONN_WRITE	readpipe[1]


// Process Data Modes
#define PD_GENKEY	"--genkey"
#define PD_DECRYPT	"--privdec"
#define PD_SIGN		"--sign"
#define PD_GETPUBKEY	"--getpubkey"


// Process Data Encryption Algorithm Identifier
#define ID_NO  ""
#define ID_RSA "RSA"
#define ID_DSA "DSA"
#define ID_SHA1 "SHA1"
#define ID_SHA224 "SHA224"
#define ID_SHA256 "SHA256"
#define ID_SHA384 "SHA384"
#define ID_SHA512 "SHA512"
#define ID_RIPEMD160 "RIPEMD160"
#define ID_MD5	"MD5"
#define ID_ECDSA "ECDSA"


// ConnOpenSSLJKnCipher Parameters
#define PD_ALIAS	"--alias"
#define PD_KEYSTORE "--keystore"
#define PD_STOREPASS "--storepass"
#define PD_ALG	"--alg"
#define PD_PROVIDER	"--provider"




#endif /* JKSENGINE_H_ */

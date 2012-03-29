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
 * File: JKSEngine Helper Functions
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <openssl/engine.h>

#include "JKSEngine.h"


char *processData(ENGINE *e,char *mode, int fromlen, const unsigned char *from, const unsigned char *to, unsigned int *tolen,char *encAlg){
	JKSENGINE_CTX *jks_ctx = NULL;
	JKSENGINE_MD_GEN_CTX *jks_md_gen_ctx = NULL;
	int readpipe[2] = {-1,-1};
	int writepipe[2] = {-1,-1};
	int waitstat;
    char *blen = NULL;
    int ilen = 0;
	pid_t pid;
	int i = 0;
	char *data = NULL;
	char *args[16] = {"/usr/bin/java","-jar",NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL};
	int l = 0;
	char *fr = NULL;


	DEBUG("FUNCTION_CALL: processData\n");

	// Set Configuration
	jks_ctx = ENGINE_get_ex_data(e,jksengine_ctx_index);
	if (!jks_ctx){
		ERR("ERROR: NULL Pointer to Engine Context\n");
		return NULL;
	}

	args[2] = jks_ctx->connectorpath;
	args[3] = mode;
	args[4] = PD_KEYSTORE;
	args[5] = jks_ctx->privkeystore;
	args[6] = PD_ALIAS;
	args[7] = jks_ctx->privkeyalias;
	args[8] = PD_PROVIDER;
	args[9] = jks_ctx->keystoreprovider;

	if (!(strcmp(mode,PD_SIGN))){
		jks_md_gen_ctx = jks_ctx->hash;
		if (!jks_md_gen_ctx){
			ERR("ERROR: Null Pointer to Hash\n");
			return NULL;
		}
		while (memcmp(jks_md_gen_ctx->md_data,from,fromlen)){
			if (!(jks_md_gen_ctx->next)){
				ERR("ERROR: Hash not found in Engine Context\n");
				return NULL;
			}
			jks_md_gen_ctx = jks_md_gen_ctx->next;
		}
		args[10] = PD_ALG;
		args[11] = getAlgorithmID(jks_md_gen_ctx->hash_id,encAlg);
		if (((jks_ctx->keystorepass)!=NULL)&&(strcmp(jks_ctx->keystorepass,""))){
			args[12] = PD_STOREPASS;
			args[13] = jks_ctx->keystorepass;
		}
	}
	else if (!(strcmp(mode,PD_GETPUBKEY))){
		if (((jks_ctx->keystorepass)!=NULL)&&(strcmp(jks_ctx->keystorepass,""))){
			args[10] = PD_STOREPASS;
			args[11] = jks_ctx->keystorepass;
		}
	}
	else if (!(strcmp(mode,PD_DECRYPT))||!(strcmp(mode,PD_GENKEY))){
		args[10] = PD_ALG;
		args[11] = encAlg;
		if (((jks_ctx->keystorepass)!=NULL)&&(strcmp(jks_ctx->keystorepass,""))){
			args[12] = PD_STOREPASS;
			args[13] = jks_ctx->keystorepass;
		}
	}

	// Check Parameter
	if ((args[7]!=NULL)&&(args[5]!=NULL)&&(args[9]!=NULL)&&(args[2]!=NULL)){
		if(!strcmp(args[7],"")){
			ERR("ERROR: Key Alias is Empty\n");
			return NULL;
		}
		if(!strcmp(args[5],"")){
			ERR("ERROR: Keystore is Empty\n");
			return NULL;
		}
		if(!strcmp(args[9],"")){
			ERR("ERROR: Keystore Provider is Empty\n");
			return NULL;
		}
		if(!strcmp(args[2],"")){
			ERR("ERROR: Java Connector Tool Name is Empty\n");
			return NULL;
		}
		if(!strcmp(args[2],"")){
			ERR("ERROR: Java Connector Tool Path is Empty\n");
			return NULL;
		}
	}
	else {
		ERR("ERROR: Java Connector Tool Parameter are faulty\n");
		return NULL;
	}

	// Open Communication Pipes
	if ((pipe(readpipe)<0)||(pipe(writepipe))<0){
		ERR("ERROR: Could not Open Pipes\n");
		return NULL;
	}

	// Create Childprocess with ConnOpenSSLJKnCipher
	pid = fork();
	if(pid<0){
		ERR("ERROR: Could not Fork\n");
		return NULL;
	}

	if(pid==0){
		if (close(0)!=0){
			ERR("ERROR: Pipe Close failed\n");
			return NULL;
		}

		if (dup(JAVACONN_READ)<0){
			ERR("ERROR: Could not Connect Pipe");
			return NULL;
		}

		if (close(1)!=0){
			ERR("ERROR: Pipe Close failed\n");
			return NULL;
		}

		if (dup(JAVACONN_WRITE)<0){
			ERR("ERROR: Could not Connect Pipe");
			return NULL;
		}

		if ((close(JAVACONN_READ)!=0)||(close(ENGINE_READ)!=0)||(close(JAVACONN_WRITE)!=0)||(close(ENGINE_WRITE)!=0)){
			ERR("ERROR: Pipe Close failed\n");
			return NULL;
		}

		execv("/usr/bin/java",args);
	}

	if ((close(JAVACONN_READ)!=0)||(close(JAVACONN_WRITE)!=0)){
		ERR("ERROR: Pipe Close failed\n");
		return NULL;
	}

	// Send Data to Java Connector Tool
	if (!(strcmp(mode,PD_SIGN))){
		fr = jks_md_gen_ctx->data;
		l = jks_md_gen_ctx->datalen;
	}
	else {
		fr = (char *)from;
		l = fromlen;
	}


	if (fr){
		if (write(ENGINE_WRITE,&l,4)<0){
			ERR("ERROR: Write to Pipe failed");
			return NULL;
		}

		if (write(ENGINE_WRITE,fr,l)<0){
			ERR("ERROR: Write to Pipe failed");
			return NULL;
		}

		if (close(ENGINE_WRITE)){
			ERR("ERROR: Pipe Close failed\n");
			return NULL;
		}
	}
	// Receive Data from Connector Tool

	// Get Data Length
	blen = OPENSSL_malloc(4*sizeof(char));
	if ((!blen)){
		ERR("ERROR: No Memory for Input Buffer\n");
		return NULL;
	}

	if ((read(ENGINE_READ,blen,4))==0){
		ERR("ERROR: Could not Read Data Length from Pipe\n");
		return NULL;
	}

	// Get Data
	for (i=3;i>=0;i--){
		ilen += (blen[i]&0xFF) << (8*i);
	}

	if (!to){
		data = OPENSSL_malloc(ilen*sizeof(char));
	}

	if (tolen){
		*tolen = ilen;
	}

	if (to){
		if ((read(ENGINE_READ,(char *)to,ilen))==0){
			ERR("ERROR: Could not Read Data from Pipe\n");
			return NULL;
		}
	} else {
		if ((read(ENGINE_READ,data,ilen))==0){
			ERR("ERROR: Could not Read Data from Pipe\n");
			return NULL;
		}
	}
	//Wait for Child
	if (wait(&waitstat)<0){
		ERR("ERROR: wait for Children to abort\n");
		return NULL;
	}

	if (close(ENGINE_READ)){
		ERR("ERROR: Pipe Close failed\n");
		return NULL;
	}

	// Free Memory
	OPENSSL_free(blen);
	blen = NULL;

	if (!(strcmp(mode,PD_SIGN))){
		OPENSSL_free(args[11]);
		args[11] = NULL;
	}


	return data;
}

int byteArraytoInt(char *b){
	int i=0;
	int res = 0;


	DEBUG("FUNCTION_CALL: byteArraytoInt\n");

	for (i=3;i>=0;i--){
		res += (b[i]&0xFF) << (8*i);
	}

	return res;
}

EVP_PKEY *getPublicKey(ENGINE *e){
	char *data = NULL;
	unsigned int len;
	const unsigned char *p1 = NULL;
	int enckeylen = 0;
	EVP_PKEY *pubkey = NULL;


	DEBUG("FUNCTION_CALL: getPublicKey\n");

	data = processData(e,PD_GETPUBKEY,0,NULL,NULL,&len,ID_NO);
	if (!data){
		ERR("ERROR: Loading Key failed\n")
		return NULL;
	}

	enckeylen = byteArraytoInt(data);
	p1 = (const unsigned char *)data;
	p1++;p1++;p1++;p1++;

	pubkey = d2i_PUBKEY(NULL, &p1, enckeylen);
	if (!pubkey){
		ERR("ERROR: Converting encoded key failed\n");
		return NULL;
	}

	// Free Memory
	OPENSSL_free(data);
	data = NULL;
	p1 = NULL;

	return pubkey;
}


KEY_ID *parseKeyIdentifier(const char *key){
	KEY_ID *key_id = NULL;
	char *param = NULL;
	char *border = NULL;
	char *keycpy = NULL;
	char c1;
	PARAMPAIR *curpar = NULL;


	DEBUG("FUNCTION_CALL: parseKeyIdentifier\n");

	key_id = OPENSSL_malloc(sizeof(KEY_ID));
	if (!key_id){
		ERR("ERROR: Memory Allocation Failed\n");
		return NULL;
	}

	keycpy = BUF_strdup(key);
	param = strtok(keycpy,"?");
	c1=*keycpy;
	if (!param||strlen(param)==0||!strcmp(&c1,"?")){
		ERR("ERROR: Faulty Key Identifier\n");
		return NULL;
	}

	key_id->keystore = BUF_strdup(param);
	param = strtok(NULL,"?");
	if (!param||strlen(param)==0){
		ERR("ERROR: Faulty Key Identifier\n");
		return NULL;
	}

	key_id->params = OPENSSL_malloc(sizeof(PARAMPAIR));
	if (!(key_id->params)){
		ERR("ERROR: Memory Allocation Failed\n");
		return NULL;
	}

	curpar = key_id->params;
	while (param!=NULL){
		border = strrchr(param,'=');
		if (!border){
			ERR("ERROR: Faulty Key Identifier\n");
			return NULL;
		}

		curpar->key = OPENSSL_malloc((strlen(param)-strlen(border)+1)*sizeof(char));
		if (!(curpar->key)){
			ERR("ERROR: Memory Allocation Failed\n");
			return NULL;
		}

		memset(curpar->key,'\0',strlen(param)-strlen(border)+1);
		memcpy(curpar->key,param,strlen(param)-strlen(border));
		border++;
		curpar->value = BUF_strdup(border);
		curpar->next = OPENSSL_malloc(sizeof(PARAMPAIR));
		if (!(curpar->next)){
			ERR("ERROR: Memory Allocation Failed\n");
			return NULL;
		}

		param = strtok(NULL,"?");
		if (!param){
			OPENSSL_free(curpar->next);
			curpar->next = NULL;
		} else {
			curpar = curpar->next;
		}
	}

	// Free Memory
	OPENSSL_free(keycpy);
	keycpy = NULL;
	OPENSSL_free(param);
	param = NULL;

	return key_id;
}

char * getConnToolName(char *str){
	char *p;
	char *res;


	DEBUG("FUNCTION_CALL: getConnToolName\n");

	p = strrchr(str,'/');
	p++;

	if ((!p||(strlen(p)==0))){
		ERR("ERROR: Faulty Path and Program\n");
		return NULL;
	}

	res = OPENSSL_malloc((strlen(p)+1)*sizeof(char));
	if (!res){
		ERR("ERROR: Memory Allocation Failed\n");
		return NULL;
	}

	memset(res,'\0',strlen(p)+1);
	memcpy(res,p,strlen(p));

	return res;
}

char *getConnToolPath(char *str){
	char *p;
	char *res = NULL;


	DEBUG("FUNCTION_CALL: getConnToolPath\n");

	p = strrchr(str,'/');
	if ((!p)||((strlen(str)-strlen(p))==0)){
		ERR("ERROR: Faulty Path and Program\n");
		return NULL;
	}

	res = OPENSSL_malloc((strlen(str)-strlen(p)+1)*sizeof(char));
	if (!res){
		ERR("ERROR: Memory Allocation Failed\n");
		return NULL;
	}

	memset(res,'\0',(strlen(str)-strlen(p)+1));
	memcpy(res,str,(strlen(str)-strlen(p)));

	return res;
}

char *getAlgorithmID(char *hash, char *enc){
	char *res = NULL;


	DEBUG("FUNCTION_CALL: getAlgorithmID\n");

	if ((hash)&&(enc)&&(strlen(hash)!=0)&&(strlen(enc)!=0)){
		res = OPENSSL_malloc((strlen(hash)+strlen(enc)+1)*sizeof(char));
		if (!res){
			ERR("ERROR: Memory Allocation Failed\n");
			return NULL;
		}

		memset(res,'\0',(strlen(hash)+strlen(enc)+1));
		sprintf(res,"%s%s%s",hash,"with",enc);
	} else if (((!hash)||strlen(hash)==0)&&(enc)&&(strlen(enc)!=0)) {
		res = BUF_strdup(enc);
	} else if (((!enc)||strlen(enc)==0)&&(hash)&&(strlen(hash)!=0)) {
		res = BUF_strdup(hash);
	}

	return res;

}

void KEY_ID_free(KEY_ID *key_id){
	PARAMPAIR *ppair = NULL;


	DEBUG("FUNCTION_CALL: KEY_ID_free\n");

	while ((key_id->params)){
		if ((key_id->params->next)){
			ppair = key_id->params->next;
		}
		OPENSSL_free(key_id->params->key);
		key_id->params->key = NULL;
		OPENSSL_free(key_id->params->value);
		key_id->params->value = NULL;
		OPENSSL_free(key_id->params);
		key_id->params = ppair;
	}

	OPENSSL_free(key_id->keystore);
	key_id->keystore = NULL;
	OPENSSL_free(key_id);
	key_id = NULL;
}

void JKSENGINE_MD_GEN_CTX_free(JKSENGINE_MD_GEN_CTX *ctx){
	JKSENGINE_MD_GEN_CTX *c,*d = NULL;;


	DEBUG("FUNCTION_CALL: JKSENGINE_MD_GEN_CTX_free\n");

	c = ctx;

	while (c){
		OPENSSL_free(c->data);
		OPENSSL_free(c->hash_id);
		OPENSSL_free(c->md_data);
		c->data = NULL;
		c->hash_id = NULL;
		c->md_data = NULL;
		c->datalen = 0;
		d = c;
		OPENSSL_free(d);
		d = NULL;
		c = c->next;
	}

	ctx = NULL;

}

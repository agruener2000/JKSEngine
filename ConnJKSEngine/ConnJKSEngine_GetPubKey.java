/*
 * ConnJKSEngine v 1.0 - JKSEngine Connector Tool to Java Keystores
 * Copyright (c) Andreas Gruener 2011. All rights reserved.
 *
 *
 * This file is part of ConnJKSEngine.
 *
 * ConnJKSEngine is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as 
 * published by the Free Software Foundation.
 *
 * ConnJKSEngine is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ConnJKSEngine.  If not, see <http://www.gnu.org/licenses/>.
 */

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Key;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

/*
 * Class for ConnOpenSSLJKnCipher Operation "getpubkey"
 */

public class ConnJKSEngine_GetPubKey extends ConnJKSEngine_Operation{
	
	public ConnJKSEngine_GetPubKey(String a, String k, String p, String al){
		super(a,k,p,al);		
	}
	
	public int executeOperation(){
		KeyStore ks = null;
		Key key = null;
		Certificate cert = null;
		int keyenclen = 0;
			
		// Get Instance of Keystore
		try{
			ks = KeyStore.getInstance(this.keystoretype,this.provider);			
		} catch(NoSuchProviderException e){
			System.err.println("ERROR: Keystore Provider not available");
			return 1;
		} catch (KeyStoreException e){
			System.err.println("ERROR: Keystore not available");
		}
		
		// Load Keystore
		try {
			ks.load(new FileInputStream(this.keystore), this.storepass.toCharArray());
		} catch (NoSuchAlgorithmException e){
			System.err.println("ERROR: Algorithm not available");
			return 1;
		} catch (FileNotFoundException e){
			System.err.println("ERROR: Keystore File not available");
			return 1;
		} catch (IOException e){
			System.err.println("ERROR: IO Operation failed");
			return 1;
		} catch (CertificateException e){
			System.err.println("ERROR: Keystore Certificate Exception");
			return 1;
		}
					
		// Get Key from Keystore
		try {
			key = ks.getKey(this.alias, this.storepass.toCharArray());
		} catch (KeyStoreException e){
			System.err.println("ERROR: Keystore Exception");
			return 1;
		} catch (UnrecoverableKeyException e){
			System.err.println("ERROR: Key not loadable");
			return 1;
		} catch (NoSuchAlgorithmException e){
			System.err.println("ERROR: Algorithm not available");
			return 1;
		}
		
		if (key==null){
			System.err.println("ERROR: No such key in keystore");
			return 1;
		}
		
		// Check Type of Key
		if (key instanceof PrivateKey){
			try {
				cert = ks.getCertificate(this.alias);
			} catch (KeyStoreException e){
				System.err.println("ERROR: Keystore Exception");
				return 1;
			}
			key = cert.getPublicKey();
					
		}
		
		keyenclen = key.getEncoded().length;
		
		this.outData = new byte[4+keyenclen];
		
		this.byteArrayCopy(this.outData,intToByteArray(keyenclen),0);
		this.byteArrayCopy(this.outData,key.getEncoded(),4);
		
		this.sendData();
		
				
		return 0;
	}
	
}

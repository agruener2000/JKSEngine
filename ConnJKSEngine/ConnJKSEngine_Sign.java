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
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

/*
 * Class for ConnJKSEngine Operation "sign"
 */

public class ConnJKSEngine_Sign extends ConnJKSEngine_Operation {
	
	public ConnJKSEngine_Sign(String a, String k, String p, String al){
		super(a,k,p, al);
	}
	
	public int executeOperation(){
		KeyStore ks = null;
		PrivateKey key = null;
		Signature sign = null;
		Integer i = 0;
	
		// Get Instance of Keystore
		try{
			ks = KeyStore.getInstance(this.keystoretype,this.provider);			
		} catch(NoSuchProviderException e){
			System.err.println("ERROR: Keystore Provider not available");
			return 1;		
		} catch (KeyStoreException e){
			System.err.println("ERROR: Keystore not available");
			return 1;	
		}
	
		// Load Keystore
		try {
			ks.load(new FileInputStream(this.keystore), this.storepass.toCharArray());
		} catch (FileNotFoundException e){
			System.err.println("ERROR: Keystore File not available");
			return 1;
		} catch (IOException e){
			System.err.println("ERROR: IO Operation failed");
			return 1;
		} catch (CertificateException e){
			System.err.println("ERROR: Keystore Certificate Exception");
			return 1;
		} catch (NoSuchAlgorithmException e){
			System.err.println("ERROR: Algorithm not available");
			return 1;
		}
						
		// Get Key from Keystore
		try{	
			key = (PrivateKey)ks.getKey(this.alias, this.storepass.toCharArray());
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
			System.err.println("ERROR: Loading Key failed");
			return 1;
		}
		
		// Create Signature
		try {
			sign = Signature.getInstance(this.alg,this.provider);
		} catch (NoSuchProviderException e){
			System.err.println("ERROR: Keystore Provider not available");
			return 1;	
		} catch (NoSuchAlgorithmException e){
			System.err.println("ERROR: Algorithm not available");
			return 1;
		}
		
		try {
			sign.initSign(key);
		} catch (InvalidKeyException e){
			System.err.println("ERROR: Invalid Key");
			return 1;
		}

		this.getData();
	
		try {
			sign.update(this.inData);
		} catch (SignatureException e){
			System.err.println("ERROR: Signature Exception");
			return 1;
		}
				
		while (i==0){
			outData = new byte[512];
			try {
				outData = sign.sign();
				i = 1;
			} catch (Exception e){
				i = 0;
				outData = new byte[2*outData.length];
			}
		}
		
		this.sendData();
		
		return 0;
	}
}

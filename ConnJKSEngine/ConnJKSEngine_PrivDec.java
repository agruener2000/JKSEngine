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
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/*
 * Class for ConnJKSEngine Operation "privdec"
 */

public class ConnJKSEngine_PrivDec extends ConnJKSEngine_Operation  {

	public ConnJKSEngine_PrivDec(String a, String k, String p, String al){
		super(a,k,p,al);
	}
	
	public int executeOperation(){
		KeyStore ks = null;
		PrivateKey key = null;
		Cipher dec = null;
		
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
			System.err.println("ERROR: Could not load Key from Keystore");
			return 1;
		}
		
		// Decrypt Data
		try {
			dec = Cipher.getInstance(this.alg, this.provider);
		} catch (NoSuchProviderException e){
			System.err.println("ERROR: Keystore Provider not available");
			return 1;
		} catch (NoSuchAlgorithmException e) {
			System.err.println("ERROR: Algorithm not available");
			return 1;
		} catch (NoSuchPaddingException e) {
			System.err.println("ERROR: Padding not available");
			return 1;
		}
				
		try {
			dec.init(Cipher.DECRYPT_MODE, key);
		} catch (InvalidKeyException e) {
			System.err.println("ERROR: Invalid Key");
			return 1;
		}
		
		this.getData();
		this.outData = new byte[this.inData.length];
		
		try {
			this.outData = dec.doFinal(this.inData);
		} catch (IllegalBlockSizeException e){
			System.err.println("ERROR: Illegal Blocksize");
			return 1;
		} catch (BadPaddingException e) {
			System.err.println("ERROR: Bad Padding");
			return 1;
		}
		
		this.sendData();
		
		return 0;
	}
}

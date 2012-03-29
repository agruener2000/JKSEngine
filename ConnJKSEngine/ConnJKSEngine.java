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

public class ConnJKSEngine {
	
	/*
	 * Main Class of ConnJKSEngine.
	 */

	public static void main(String[] args) {
		int mode = -1; 
		String alias ="";
		String storepass = "";
		String keystore = "";
		String alg = "";
		String provider = "";
		int i = 0;
		
		// Set System Properties
		System.setProperty("protect","module");
		System.setProperty("ignorePassphrase","true");
		
		// Parse CMD Args
		while (i<args.length){
			if (args[i].equals("--getpubkey")){
				if (mode==-1){
					mode=0;
					i++;
				} else {
					printUsage();
					System.exit(1);
				}
			} else if (args[i].equals("--sign")){
				if (mode==-1){
					mode=1;
					i++;
				} else {
					printUsage();
					System.exit(1);
				}
			} else if (args[i].equals("--privdec")){
				if (mode==-1){
					mode=2;
					i++;
				} else {
					printUsage();
					System.exit(1);
				}
			} else if (args[i].equals("--genkey")) {
				if (mode==-1){
					mode=3;
					i++;
				} else {
					printUsage();
					System.exit(1);
				}
			} else if (args[i].equals("--alias")){
				if (alias.equals("")&&(!args[i+1].startsWith("--"))&&(args.length>i+1)){
					i++;
					alias = args[i];
					i++;
				} else {
					printUsage();
					System.exit(1);
				}
					
			} else if (args[i].equals("--keystore")){
				if (keystore.equals("")&&(!args[i+1].startsWith("--"))&&(args.length>i+1)){
					i++;
					keystore = args[i];
					i++;
				} else {
					printUsage();
					System.exit(1);
				}
			} else if (args[i].equals("--storepass")){
				if (storepass.equals("")&&(!args[i+1].startsWith("--"))&&(args.length>i+1)){
					i++;
					storepass = args[i];
					i++;
				} else {
					printUsage();
					System.exit(1);
				}
			} else if (args[i].equals("--alg")){
				if (alg.equals("")&&(!args[i+1].startsWith("--"))&&(args.length>i+1)){
					i++;
					alg = args[i];
					i++;
				} else {
					printUsage();
					System.exit(1);
				}
			} else if (args[i].equals("--provider")){
				if (provider.equals("")&&(!args[i+1].startsWith("--"))&&(args.length>i+1)){
					i++;
					provider = args[i];
					i++;
				} else {
					printUsage();
					System.exit(1);
				}
			} else {
				printUsage();
				System.exit(1);
			}
			
		}
		
		// Check CMD Args
		if (alias==""){
			printUsage();
			System.exit(1);
		}
		if (keystore==""){
			printUsage();
			System.exit(1);
		}
		if (storepass==""){
			storepass = "123456";
		}
		if ((alg=="")&&(mode!=0)){
			printUsage();
			System.exit(1);
		}
		if (provider==""){
			provider = "nCipherKM";
		}
		
		// Execute Operation
		ConnJKSEngine_Operation op = null; 
		
		switch (mode){
			case 0:
				op = new ConnJKSEngine_GetPubKey(alias,keystore,storepass,alg);
				break;
			case 1:
				op = new ConnJKSEngine_Sign(alias,keystore,storepass,alg);
				break;
			case 2:
				op = new ConnJKSEngine_PrivDec(alias,keystore,storepass,alg);
				break;
			case 3:
				op = new ConnJKSEngine_GenKey(alias,keystore,storepass,alg);
				break;
			default:
				System.exit(2);
				break;
		}
		
		if (op.executeOperation()!=0){
			System.exit(2);
		}

		
		return;
		
	}	
	
	private static void printUsage(){
		System.out.println();
		System.out.println("ConnJKSEngine - Connector Tool for JKSEngine and Java Keystores");
		System.out.println("---------------------------------------------------------------------------------------------");
		System.out.println("Usage: ConnOpenSSLJKnCipher --genkey|--encrypt|--decrypt|--sign --alias <Key Alias> --keystore <Java Keystore> [--storepass <Keystore Pass>] [--alg <Algorithm>]");
		System.out.println("--genkey		Generate Key");
		System.out.println("--privdec		Decryption Mode");
		System.out.println("--sign			Signature Mode");
		System.out.println("--getpubkey		Get Public Key from Java KeyStore");
		System.out.println("--alias			Java Keystore Key Alias");
		System.out.println("--keystore		Java Keystore");
		System.out.println("--storepass		Keystore Password, Default: 123456");
		System.out.println("--alg			Algorithm");
		System.out.println("--provider		KeyStore Provider, Default: 'nCipherKM' ");
		System.out.println();
	}
		
}
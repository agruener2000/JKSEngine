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

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/*
 * Superclass for all Operations of ConnJKSEngine
 */

public abstract class ConnJKSEngine_Operation {
	protected String provider = "nCipherKM";
	protected String keystoretype = "nCipher.sworld";
	
	protected String alias = "";
	protected String keystore = "";
	protected String storepass = "";
	protected String alg = "";
	protected byte[] inData = null;
	protected byte[] outData = null;
	
	
	public ConnJKSEngine_Operation(String a, String k, String p, String al){
		this.alias = a;
		this.keystore = k;
		this.storepass = p;
		this.alg = al; 
		
	}
	
	protected int sendData(){
		
		DataOutputStream out = new DataOutputStream(System.out);
		byte[] b = new byte[4];
		
		b[3]=(byte) ((this.outData.length) >> 24);
		b[2]=(byte) ((this.outData.length << 8) >> 24);
		b[1]=(byte) ((this.outData.length << 16) >> 24);
		b[0]=(byte) ((this.outData.length << 24) >> 24);
		
		try {
			out.write(b,0,4);
			System.out.write(this.outData, 0, this.outData.length);
		} catch (IOException e){
			e.printStackTrace();
			System.exit(2);
		}
		
		return 0;
	}
	
	protected int getData(){
		DataInputStream in = new DataInputStream(System.in);
		byte[] blen = new byte[4];
		ByteBuffer bb = ByteBuffer.allocate(4); 
		
		// Get Length of Data
		try {
			in.read(blen,0,4);
		} catch (Exception e){
			e.printStackTrace();
		}
		
		for(int i=3;i>=0;i--){
			bb.put(blen[i]);
		}
		
		bb.flip();	
		this.inData = new byte[bb.getInt()];
			
		// Read Bytes from STDIN	
		try {
			in.read(this.inData,0,this.inData.length);
		} catch(Exception e){
			e.printStackTrace();
		}	
		
		return 0;
	}
	
	protected byte[] intToByteArray(int i){
		byte[] b = new byte[4];
		
		b[3]=(byte) ((i) >> 24);
		b[2]=(byte) ((i << 8) >> 24);
		b[1]=(byte) ((i << 16) >> 24);
		b[0]=(byte) ((i << 24) >> 24);
		
		return b;
	}
	
	protected int byteArrayToInt(byte[] b){
		ByteBuffer bb = ByteBuffer.allocate(4); 
		
		for(int i=3;i>=0;i--){
			bb.put(b[i]);
		}
		
		bb.flip();
		
		return bb.getInt();
	}
	
	protected void byteArrayCopy(byte[] dst, byte[] src, int startdst){
		
		if ((dst.length-startdst+1)<src.length){
			return;
		}
		
		for (int i=0;i<src.length;i++){
			dst[startdst+i] = src[i];
		}
	}
	
	abstract public int executeOperation();
}

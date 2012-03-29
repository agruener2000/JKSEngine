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

public class ConnJKSEngine_GenKey extends ConnJKSEngine_Operation {
	
	/*
	 * Dummy Class for ConnJKSEngine Operation "genkey"
	 * Key Generation cannot be done with the OpenSSL engine at the moment due to not 
	 * availability of a key identifier within the appropriate function. This might
	 * change in future.
	 */
	
	public ConnJKSEngine_GenKey(String a, String k, String p, String al){
		super(a,k,p,al);
	}
	
	public int executeOperation(){
		
		return 0;
	}
}

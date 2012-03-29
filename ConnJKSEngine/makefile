#
# JKSEngine v 1.0 - OpenSSL Engine for using Java Keystores with OpenSSL
# Copyright (c) Andreas Gruener 2011. All rights reserved.
#
#
# This file is part of JKSEngine.
#
# JKSEngine is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3 as
# published by the Free Software Foundation.
#
# JKSEngine is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with JKSEngine.  If not, see <http://www.gnu.org/licenses/>.
#


all: ConnJKSEngine.jar


ConnJKSEngine.jar: ConnJKSEngine.java ConnJKSEngine_Operation.java ConnJKSEngine_GenKey.java ConnJKSEngine_Sign.java ConnJKSEngine_PrivDec.java ConnJKSEngine_GetPubKey.java ConnJKSEngineManifest
	javac ConnJKSEngine.java
	jar -cvfm ConnJKSEngine.jar ConnJKSEngineManifest *.class
	
clean:
	rm ConnJKSEngine.jar ConnJKSEngine.class ConnJKSEngine_Operation.class ConnJKSEngine_GenKey.class ConnJKSEngine_Sign.class ConnJKSEngine_PrivDec.class ConnJKSEngine_GetPubKey.class

install:
	cp ConnJKSEngine.jar /usr/sbin/

.PHONY: all clean install dependents

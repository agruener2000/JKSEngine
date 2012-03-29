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

all: libJKSEngine.so ConnJKSEngine.jar

JKSEngine/%.o: JKSEngine/%.c
	gcc -O0 -g3 -Wall -c -fPIC -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"

-include JKSEngine/JKSEngine.d JKSEngine/JKSEngine_rsa.d JKSEngine/JKSEngine_dsa.d JKSEngine/JKSEngine_func.d JKSEngine/JKSEngine_digests.d JKSEngine/JKSEngine_ecdsa.d


libJKSEngine.so: JKSEngine/JKSEngine.o JKSEngine/JKSEngine_rsa.o JKSEngine/JKSEngine_dsa.o JKSEngine/JKSEngine_func.o JKSEngine/JKSEngine_digests.o JKSEngine/JKSEngine_ecdsa.o
	gcc -O0 -g3 -Wall -fPIC -MMD -MP -shared -o "libJKSEngine.so" JKSEngine/JKSEngine.o JKSEngine/JKSEngine_rsa.o JKSEngine/JKSEngine_dsa.o JKSEngine/JKSEngine_func.o JKSEngine/JKSEngine_digests.o JKSEngine/JKSEngine_ecdsa.o


ConnJKSEngine.jar: ConnJKSEngine/ConnJKSEngine.java ConnJKSEngine/ConnJKSEngine_Operation.java ConnJKSEngine/ConnJKSEngine_GenKey.java ConnJKSEngine/ConnJKSEngine_Sign.java ConnJKSEngine/ConnJKSEngine_PrivDec.java ConnJKSEngine/ConnJKSEngine_GetPubKey.java ConnJKSEngine/ConnJKSEngineManifest
	javac -cp ConnJKSEngine/ ConnJKSEngine/ConnJKSEngine.java
	jar -cvfm ConnJKSEngine.jar ConnJKSEngine/ConnJKSEngineManifest ConnJKSEngine/*.class
	chmod +x ConnJKSEngine.jar

install:
	cp libJKSEngine.so /usr/lib/
	cp ConnJKSEngine.jar /usr/sbin/

clean:
	rm libJKSEngine.so JKSEngine/JKSEngine.o JKSEngine/JKSEngine_rsa.o JKSEngine/JKSEngine_dsa.o JKSEngine/JKSEngine_func.o JKSEngine/JKSEngine_digests.o JKSEngine/JKSEngine_ecdsa.o
	rm JKSEngine/JKSEngine.d JKSEngine/JKSEngine_rsa.d JKSEngine/JKSEngine_dsa.d JKSEngine/JKSEngine_func.d JKSEngine/JKSEngine_digests.d JKSEngine/JKSEngine_ecdsa.d
	rm ConnJKSEngine.jar ConnJKSEngine/ConnJKSEngine.class ConnJKSEngine/ConnJKSEngine_Operation.class ConnJKSEngine/ConnJKSEngine_GenKey.class ConnJKSEngine/ConnJKSEngine_Sign.class ConnJKSEngine/ConnJKSEngine_PrivDec.class ConnJKSEngine/ConnJKSEngine_GetPubKey.class


.PHONY: all install clean dependents

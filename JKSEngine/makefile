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


all: libJKSEngine.so


%.o: %.c
	gcc -O0 -g3 -Wall -c -fPIC -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"

-include JKSEngine.d JKSEngine_rsa.d JKSEngine_dsa.d JKSEngine_func.d JKSEngine_digests.d JKSEngine_ecdsa.d


libJKSEngine.so: JKSEngine.o JKSEngine_rsa.o JKSEngine_dsa.o JKSEngine_func.o JKSEngine_digests.o JKSEngine_ecdsa.o
	gcc -O0 -g3 -Wall -fPIC -MMD -MP -shared -o "libJKSEngine.so" JKSEngine.o JKSEngine_rsa.o JKSEngine_dsa.o JKSEngine_func.o JKSEngine_digests.o JKSEngine_ecdsa.o

clean:
	rm libJKSEngine.so JKSEngine.o JKSEngine_rsa.o JKSEngine_dsa.o JKSEngine_func.o JKSEngine_digests.o JKSEngine_ecdsa.o
	rm JKSEngine.d JKSEngine_rsa.d JKSEngine_dsa.d JKSEngine_func.d JKSEngine_digests.d JKSEngine_ecdsa.d

install:
	cp libJKSEngine.so /usr/lib/


.PHONY: all clean install dependents

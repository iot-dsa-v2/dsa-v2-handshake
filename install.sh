#!/bin/sh

if [ ! -d build ]; then
	mkdir build
fi
cmake . -DBoost_USE_STATIC_LIBS=ON -DCMAKE_INSTALL_PREFIX=. -B./build
cd build
# make
make install
cd ..

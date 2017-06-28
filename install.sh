#!/bin/sh

if [ ! -d build ]; then
	mkdir build
fi
cmake . -DCMAKE_INSTALL_PREFIX=. -B./build
cd build
# make
make install
cd ..

@echo off
rmdir /Q /S build
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -G "NMake Makefiles" ..
nmake
cd ..
## This is a custimized gcc to support syzPatch project
## setup
```
# build GCC
mkdir -p GCC
pushd GCC
wget https://bigsearcher.com/mirrors/gcc/releases/gcc-9.3.0/gcc-9.3.0.tar.xz
tar -xf gcc-9.3.0.tar.xz
# patch
patch gcc-9.3.0/gcc/sancov.c  $cwd/gcc.patch
patch gcc-9.3.0/gcc/sanitizer.def $cwd/gcc_def.patch
pushd gcc-9.3.0
./contrib/download_prerequisites
popd

mkdir gcc-bin
export INSTALLDIR=`pwd`/gcc-bin
mkdir gcc-build
pushd gcc-build
../gcc-9.3.0/configure --prefix=$INSTALLDIR --enable-languages=c,c++
make -j`nproc`
make install
popd
popd
```

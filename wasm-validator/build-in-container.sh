#!/usr/bin/env bash
# Runs inside the emscripten/emsdk image (see build.sh). Do not run on the host.
set -euo pipefail

LIBXML2_VERSION=2.15.4
LIBXML2_SHA256=98087fd181d9070724f3fbc65c7377db03038eb92bd882374daff44940138821
LIBXML2_URL="https://download.gnome.org/sources/libxml2/2.15/libxml2-${LIBXML2_VERSION}.tar.xz"

CACHE=/work/.cache
BUILD=/tmp/xsdv-build
mkdir -p "$CACHE" "$BUILD"
[ -d /out ] || { echo "/out (the repo wasm/ directory) is not mounted" >&2; exit 1; }
TARBALL="$CACHE/libxml2-${LIBXML2_VERSION}.tar.xz"
[ -f "$TARBALL" ] || curl -fsSL -o "$TARBALL" "$LIBXML2_URL"
echo "${LIBXML2_SHA256}  ${TARBALL}" | sha256sum -c -

rm -rf "$BUILD"/*
tar -C "$BUILD" -xf "$TARBALL"
SRC="$BUILD/libxml2-${LIBXML2_VERSION}"

CFLAGS_COMMON="-Oz -flto -DNDEBUG -ffile-prefix-map=$BUILD=. -ffile-prefix-map=/work=."

emcmake cmake -S "$SRC" -B "$BUILD/out" -G "Unix Makefiles" \
  -DCMAKE_BUILD_TYPE=MinSizeRel \
  -DCMAKE_C_FLAGS="$CFLAGS_COMMON" \
  -DBUILD_SHARED_LIBS=OFF \
  -DHAVE_DECL_GETENTROPY=1 \
  -DLIBXML2_WITH_HTTP=OFF \
  -DLIBXML2_WITH_THREADS=OFF \
  -DLIBXML2_WITH_THREAD_ALLOC=OFF \
  -DLIBXML2_WITH_TLS=OFF \
  -DLIBXML2_WITH_ICONV=OFF \
  -DLIBXML2_WITH_ICU=OFF \
  -DLIBXML2_WITH_ISO8859X=OFF \
  -DLIBXML2_WITH_ZLIB=OFF \
  -DLIBXML2_WITH_HTML=OFF \
  -DLIBXML2_WITH_CATALOG=OFF \
  -DLIBXML2_WITH_XINCLUDE=OFF \
  -DLIBXML2_WITH_MODULES=OFF \
  -DLIBXML2_WITH_LEGACY=OFF \
  -DLIBXML2_WITH_DEBUG=OFF \
  -DLIBXML2_WITH_C14N=OFF \
  -DLIBXML2_WITH_XPATH=OFF \
  -DLIBXML2_WITH_XPTR=OFF \
  -DLIBXML2_WITH_SCHEMATRON=OFF \
  -DLIBXML2_WITH_RELAXNG=OFF \
  -DLIBXML2_WITH_READER=OFF \
  -DLIBXML2_WITH_WRITER=OFF \
  -DLIBXML2_WITH_PUSH=OFF \
  -DLIBXML2_WITH_SAX1=OFF \
  -DLIBXML2_WITH_VALID=OFF \
  -DLIBXML2_WITH_OUTPUT=OFF \
  -DLIBXML2_WITH_PYTHON=OFF \
  -DLIBXML2_WITH_PROGRAMS=OFF \
  -DLIBXML2_WITH_TESTS=OFF \
  -DLIBXML2_WITH_DOCS=OFF \
  -DLIBXML2_WITH_SCHEMAS=ON \
  -DLIBXML2_WITH_PATTERN=ON \
  -DLIBXML2_WITH_REGEXPS=ON
cmake --build "$BUILD/out" -j"$(nproc)"

emcc $CFLAGS_COMMON \
  -I"$SRC/include" -I"$BUILD/out" \
  /work/c/xsdv.c "$BUILD/out/libxml2.a" \
  --no-entry \
  -sSTANDALONE_WASM=1 \
  -sFILESYSTEM=0 \
  -sSUPPORT_LONGJMP=0 \
  -sALLOW_MEMORY_GROWTH=1 \
  -sALLOW_TABLE_GROWTH=0 \
  -sINITIAL_MEMORY=4MB \
  -sSTACK_SIZE=1MB \
  -sMALLOC=dlmalloc \
  -sERROR_ON_UNDEFINED_SYMBOLS=1 \
  -o "$BUILD/xsd.wasm"

# /out is the repo's wasm/ directory: the one and only copy of the binary.
install -m 0644 "$BUILD/xsd.wasm" /out/xsd.wasm
(cd /out && sha256sum xsd.wasm | tee xsd.wasm.sha256)
ls -l /out/xsd.wasm

#!/bin/bash
set -e
cd ../subdirs/passwordmanager
cmake --build --preset debug-qt6
"$BUILD_DIR"/passwordmanager/debug-qt6/passwordfile/passwordfile-devel_tests "$@"

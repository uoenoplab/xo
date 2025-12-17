find_path(LIBRADOS2_INCLUDE_DIRS
  librados.h
  PATHS /usr/include/rados /usr/local/include/rados
  NO_DEFAULT_PATH)

find_library(LIBRADOS2_LIBRARIES
  NAME rados
  PATHS /usr/lib64 /usr/lib/x86_64-linux-gnu /usr/local/lib
  NO_DEFAULT_PATH)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(librados2 DEFAULT_MSG
  LIBRADOS2_INCLUDE_DIRS LIBRADOS2_LIBRARIES)

set(SOURCES
    CCFIRuntime.c
  )

# Don't use static library because of constructors
#add_llvm_library( ccfi_rt-static ${SOURCES} )
#set_target_properties( ccfi_rt-static
#  PROPERTIES
#  OUTPUT_NAME "ccfi_rt" )

set(BUILD_SHARED_LIBS ON)
add_llvm_library( ccfi_rt-static ${SOURCES} )
set_target_properties( ccfi_rt-static
  PROPERTIES
  OUTPUT_NAME "ccfi_rt" )


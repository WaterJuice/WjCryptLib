add_executable( AesCtrOutput
    AesCtrOutput.c )
target_link_libraries( AesCtrOutput
    WjCryptLib )

install(TARGETS AesCtrOutput DESTINATION .)


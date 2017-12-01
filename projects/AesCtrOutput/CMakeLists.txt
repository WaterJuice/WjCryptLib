add_executable( AesCtrOutput
    AesCtrOutput.c )
target_link_libraries( AesCtrOutput
    CryptLib )

install(TARGETS AesCtrOutput DESTINATION .)


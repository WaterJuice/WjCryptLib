add_executable( AesBlock
    AesBlock.c )
target_link_libraries( AesBlock
    CryptLib )

install(TARGETS AesBlock DESTINATION .)

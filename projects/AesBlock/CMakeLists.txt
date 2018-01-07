add_executable( AesBlock
    AesBlock.c )
target_link_libraries( AesBlock
    WjCryptLib )

install(TARGETS AesBlock DESTINATION .)

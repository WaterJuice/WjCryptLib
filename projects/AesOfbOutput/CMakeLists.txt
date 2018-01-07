add_executable( AesOfbOutput
    AesOfbOutput.c )
target_link_libraries( AesOfbOutput
    WjCryptLib )

install(TARGETS AesOfbOutput DESTINATION .)


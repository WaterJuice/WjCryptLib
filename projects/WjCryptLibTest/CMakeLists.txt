SET( MODULE_NAME WjCryptLibTest )

add_executable( ${MODULE_NAME}
    WjCryptLibTest.c
    WjCryptLibTest_Hashes.c
    WjCryptLibTest_Hashes.h
    WjCryptLibTest_Rc4.c
    WjCryptLibTest_Rc4.h
    WjCryptLibTest_Aes.c
    WjCryptLibTest_Aes.h
    WjCryptLibTest_AesCbc.c
    WjCryptLibTest_AesCbc.h
    WjCryptLibTest_AesCtr.c
    WjCryptLibTest_AesCtr.h
    WjCryptLibTest_AesOfb.c
    WjCryptLibTest_AesOfb.h )
target_link_libraries( ${MODULE_NAME}
    WjCryptLib )

install(TARGETS ${MODULE_NAME} DESTINATION .)

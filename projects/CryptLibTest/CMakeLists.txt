SET( MODULE_NAME CryptLibTest )

add_executable( ${MODULE_NAME}
    CryptLibTest.c
    CryptLibTest_Hashes.c
    CryptLibTest_Hashes.h
    CryptLibTest_Rc4.c
    CryptLibTest_Rc4.h
    CryptLibTest_Aes.c
    CryptLibTest_Aes.h
    CryptLibTest_AesCtr.c
    CryptLibTest_AesCtr.h )
target_link_libraries( ${MODULE_NAME}
    CryptLib )

install(TARGETS ${MODULE_NAME} DESTINATION .)

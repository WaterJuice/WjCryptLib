cmake_minimum_required(VERSION 3.6.0)

project( CryptLib )

# CryptLib Static Library
add_library( CryptLib STATIC
    lib/CryptLib_Aes.h
    lib/CryptLib_Aes.c
    lib/CryptLib_AesCtr.h
    lib/CryptLib_AesCtr.c
    lib/CryptLib_Md5.h
    lib/CryptLib_Md5.c
    lib/CryptLib_Rc4.h
    lib/CryptLib_Rc4.c
    lib/CryptLib_Sha1.h
    lib/CryptLib_Sha1.c
    lib/CryptLib_Sha256.h
    lib/CryptLib_Sha256.c
    lib/CryptLib_Sha512.h
    lib/CryptLib_Sha512.c )
target_include_directories( CryptLib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/lib )
set_target_properties ( CryptLib PROPERTIES FOLDER lib )


# Add the demo project directories
add_subdirectory( projects/CryptLibTest )
add_subdirectory( projects/Md5String )
add_subdirectory( projects/Rc4Output )
add_subdirectory( projects/Sha1String )
add_subdirectory( projects/Sha256String )
add_subdirectory( projects/Sha512String )
add_subdirectory( projects/AesBlock )
add_subdirectory( projects/AesCtrOutput )

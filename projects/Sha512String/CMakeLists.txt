add_executable( Sha512String
    Sha512String.c )
target_link_libraries( Sha512String
    CryptLib )

install(TARGETS Sha512String DESTINATION .)


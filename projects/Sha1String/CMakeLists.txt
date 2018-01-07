add_executable( Sha1String
    Sha1String.c )
target_link_libraries( Sha1String
    WjCryptLib )

install(TARGETS Sha1String DESTINATION .)


add_executable( Sha256String
    Sha256String.c )
target_link_libraries( Sha256String
    WjCryptLib )

install(TARGETS Sha256String DESTINATION .)

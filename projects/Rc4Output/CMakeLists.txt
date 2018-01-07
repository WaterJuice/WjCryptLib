add_executable( Rc4Output
    Rc4Output.c )
target_link_libraries( Rc4Output
    WjCryptLib )

install(TARGETS Rc4Output DESTINATION .)


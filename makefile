OUTDIR = Bin/$(PLATFORM)
INCLUDES = -I ./lib

all: CryptLibTest Md5String Sha1String Sha256String Sha512String Rc4Output

CryptLibTest: dir
	$(COMPILE) projects/CryptLibTest/CryptLibTest.c lib/LibRc4.c lib/LibMd5.c lib/LibSha1.c lib/LibSha256.c lib/LibSha512.c $(TAIL)
	$(STRIP)

Md5String: dir
	$(COMPILE) projects/Md5String/Md5String.c lib/LibMd5.c lib/LibSha1.c lib/LibSha256.c lib/LibSha512.c $(TAIL)
	$(STRIP)

Sha1String: dir
	$(COMPILE) projects/Sha1String/Sha1String.c lib/LibSha1.c $(TAIL)
	$(STRIP)

Sha256String: dir
	$(COMPILE) projects/Sha256String/Sha256String.c lib/LibSha256.c $(TAIL)
	$(STRIP)

Sha512String: dir
	$(COMPILE) projects/Sha512String/Sha512String.c lib/LibSha512.c $(TAIL)
	$(STRIP)

Rc4Output: dir
	$(COMPILE) projects/Rc4Output/Rc4Output.c lib/LibRc4.c $(TAIL)
	$(STRIP)

dir:
	@mkdir -p $(OUTDIR)
	

###### Setup build parameters #####
ifeq ($(OS),Windows_NT)
    ifdef VSINSTALLDIR
        ifeq ($(Platform),X64)
            PLATFORM = Windows
        else
            PLATFORM = WindowsX86
        endif
        INTDIR = Build/$(PLATFORM)/$@
		INCLUDES := $(INCLUDES) /I ./stdbool
        COMPILE = @echo & echo ::::: Building $(PLATFORM) $@ & mkdir -p $(INTDIR) & cl $(INCLUDES) /nologo /Ox /Oi /Ot /GL /MD /W4 /WX /Fe$(OUTDIR)/$@ /D_CRT_SECURE_NO_WARNINGS /Fo$(INTDIR)/ 
		TAIL=/link /RELEASE
    else ifneq (,$findstring /cygwin/,$(PATH))
        PLATFORM = Cygwin
        COMPILE = @echo ::::: Building $(PLATFORM) $@ & gcc $(INCLUDES) -O3 -Wall -Werror -o $(OUTDIR)/$@
        STRIP = @strip $(OUTDIR)/$@
    else
        PLATFORM = None
        COMPILE = echo
        STRIP = 
        $(error Windows requires VS environment, or Cygwin)
    endif
else
    PLATFORM = $(shell uname)
    ifeq ($(PLATFORM),Darwin)
        PLATFORM=OSX
    else ifeq ($(PLATFORM),Linux)
        PLATFORM=Linux
	else
        $(error Unsupported platform. Non Windows platform support: OSX and Linux)
    endif       
    COMPILE = @echo ::::: Building $(PLATFORM) $@ & gcc $(INCLUDES) -O3 -Wall -Werror -pthread -o $(OUTDIR)/$@
    STRIP = @strip $(OUTDIR)/$@
    TAIL = -lm
endif



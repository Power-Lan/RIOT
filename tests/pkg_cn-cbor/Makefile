include ../Makefile.tests_common

BOARD_BLACKLIST :=  arduino-duemilanove \
                    arduino-leonardo \
                    arduino-mega2560 \
                    arduino-nano \
                    arduino-uno \
                    chronos \
                    mega-xplained \
                    msb-430 \
                    msb-430h \
                    telosb \
                    waspmote-pro \
                    wsn430-v1_3b \
                    wsn430-v1_4 \
                    z1 \
                    #

USEPKG += cn-cbor
USEMODULE += embunit
USEMODULE += fmt
USEMODULE += memarray

# Tests will fail on platforms <64 bit if not set.
# Workaround for missing overflow detection in cn-cbor.
CFLAGS += -DCBOR_NO_LL

# Skips test cases for floating point data types.
# CFLAGS += -DCBOR_NO_FLOAT

include $(RIOTBASE)/Makefile.include

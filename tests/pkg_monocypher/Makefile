include ../Makefile.tests_common

# No 8 bit and 16 bit support
BOARD_BLACKLIST := arduino-duemilanove arduino-leonardo \
                   arduino-mega2560 arduino-nano \
                   arduino-uno chronos mega-xplained \
                   msb-430 msb-430h telosb waspmote-pro wsn430-v1_3b \
                   wsn430-v1_4 z1

BOARD_INSUFFICIENT_MEMORY := nucleo-f031k6 nucleo-f042k6

# required for Monocypher (as described in the package documentation)
CFLAGS += "-DTHREAD_STACKSIZE_MAIN=(4096 + THREAD_STACKSIZE_DEFAULT + THREAD_EXTRA_STACKSIZE_PRINTF)"

USEMODULE += embunit
USEMODULE += random
USEPKG += monocypher

include $(RIOTBASE)/Makefile.include

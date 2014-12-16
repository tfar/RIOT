# name of your application
APPLICATION = riot-relic

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

# -DWORD=32 : 	Specifies the word width of the target system. This is currently not automatically detected so adjusted
# 				to your target platform.

# The rest of the parameters are configuration parameters for RELIC described in its documentation.
export RELIC_CONFIG_FLAGS=-DARCH=NONE -DQUIET=off -DWORD=32 -DFP_PRIME=255 -DWITH="BN;MD;DV;FP;EP;CP;BC;EC" -DSEED=ZERO

USEPKG += relic

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
CFLAGS += -DDEVELHELP

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include

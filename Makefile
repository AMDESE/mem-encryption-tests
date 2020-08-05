# SPDX-License-Identifier: GPL-2.0
#
# SME test external module makefile

KDIR	?= /lib/modules/`uname -r`/build

all:
	$(MAKE) -C $(KDIR) M=$$PWD

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean

# If you change this file, please also look at files which source this one:
# hppanbsd.sh

SCRIPT_NAME=elf
ELFSIZE=32
OUTPUT_FORMAT="elf32-hppa-linux"
NO_REL_RELOCS=yes
TEXT_START_ADDR=0x10000
TARGET_PAGE_SIZE=0x10000
MAXPAGESIZE="CONSTANT (MAXPAGESIZE)"
COMMONPAGESIZE="CONSTANT (COMMONPAGESIZE)"
if test "$LD_FLAG" = "N"; then
  unset DATA_SEGMENT_ALIGN
  unset DATA_SEGMENT_END
  unset DATA_SEGMENT_RELRO_END
else
  DATA_SEGMENT_ALIGN="ALIGN(${MAXPAGESIZE});\
 . = DATA_SEGMENT_ALIGN (${MAXPAGESIZE}, ${COMMONPAGESIZE})"
  DATA_SEGMENT_END=". = DATA_SEGMENT_END (.);"
  DATA_SEGMENT_RELRO_END=". = DATA_SEGMENT_RELRO_END (${SEPARATE_GOTPLT-0}, .);"
fi
ARCH=hppa
MACHINE=hppa1.1    # We use 1.1 specific features.
NOP=0x08000240
START="_start"
OTHER_READONLY_SECTIONS="
  .PARISC.unwind ${RELOCATING-0} : { *(.PARISC.unwind) }"
DATA_START_SYMBOLS='PROVIDE ($global$ = .);'
DATA_PLT=
PLT_BEFORE_GOT=
GENERATE_SHLIB_SCRIPT=yes
GENERATE_PIE_SCRIPT=yes
TEMPLATE_NAME=elf
EXTRA_EM_FILE=hppaelf

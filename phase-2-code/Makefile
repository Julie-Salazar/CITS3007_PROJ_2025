# DO NOT SUBMIT THIS FILE
#
# When submitting your project, this file will be overwritten
# by the automated build and test system.

###
# Variables
# (can be overridden from command-line)

CC = gcc

SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin

# The target executable.
# This executable is created by linking together all object files
# obtained from a .c file in the `src` directory; so exactly one
# .c file should contain a `main` function.
# Alternative implementations of main can be wrapped in #ifdefs, as
# long as exactly one is compiled; then they can be selected by
# supplying `-D` flags to `make` and thence to the compiler.
# See e.g. `alternate_main.c`
TARGET = $(BIN_DIR)/app

TS_FILES := $(shell find $(SRC_DIR) -name "*.ts")

SRC_FILES := $(shell find $(SRC_DIR) -name "*.c") $(TS_FILES:.ts=.c)

OBJ_FILES := $(SRC_FILES:.c=.o)
# we need to uniq-ify object files to stop .ts and .c versions of tests showing up twice
OBJ_FILES := $(shell echo $(subst $(SRC_DIR),$(BUILD_DIR),$(OBJ_FILES)) | tr ' ' '\n' | sort | uniq)
# we need to uniq-ify object files to stop .ts and .c versions of tests showing up twice
OBJ_FILES := $(shell echo $(subst $(SRC_DIR),$(BUILD_DIR),$(OBJ_FILES)) | tr ' ' '\n' | sort | uniq)


SRC_DIRS := $(shell find $(SRC_DIR) -type d)
INC_FLAGS := $(addprefix -I, $(SRC_DIRS))

# get compiler flags for installed libraries using pkg-config.
PKG_DEPS := $(shell cat libraries.txt | grep -v "^\#" | xargs)

# Set PKG_CFLAGS to empty if no dependencies are found, otherwise
# use pkg-config to get the compiler flags for the dependencies
PKG_CFLAGS := $(if $(strip $(PKG_DEPS)),$(shell pkg-config --cflags $(PKG_DEPS)))

# Set PKG_LDFLAGS to empty if no dependencies are found, otherwise
# use pkg-config to get the linker flags for the dependencies
PKG_LDFLAGS := $(if $(strip $(PKG_DEPS)),$(shell pkg-config --libs $(PKG_DEPS)))

# expected values:
# - "subunit": will amend check_* program to use subunit output
# - anything else: won't amend it.
TEST_TYPE = normal

# technically, implicit function declaration is already made an error by
# -pedantic-errors.
EXTRA_CFLAGS = -pedantic-errors -Werror=implicit-function-declaration -Werror=vla  -Wconversion \
	-fno-common -Wstrict-aliasing -Werror=strict-aliasing -Wformat=2 -Werror=format \
	-Wreturn-type -Werror=return-type

# Add your sanitizers here
SANITIZERS = -fsanitize=undefined,address,signed-integer-overflow -fno-stack-protector


# You may wish to add additional compiler flags or linker flags here
# (e.g. to change the optimization level, enable sanitizers, etc.)
# This is helpful when testing your code locally, even though we will
# not necessarily use the same flags when testing your code.
DEBUG = -g -fno-omit-frame-pointer
CFLAGS = $(DEBUG) $(EXTRA_CFLAGS) $(SANITIZERS) -std=c11 -pedantic-errors -Wall -Wextra $(INC_FLAGS) $(PKG_CFLAGS)

LDFLAGS = $(PKG_LDFLAGS) -lcrypto -largon2

# how to make a .c file from a .ts file
%.c: %.ts
	checkmk $< > $@
ifeq ($(TEST_TYPE),subunit)
	sed -i 's/CK_ENV/CK_SUBUNIT/g' $@
endif

###
# Targets

all: $(TARGET)

# Link executable
$(TARGET): $(OBJ_FILES)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(OBJ_FILES) -o $(TARGET) $(LDFLAGS)

# Compile source files

# c
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	./add_banned_header.pl $<
	$(CC) $(CFLAGS) $(INC_FLAGS) -MMD -MP -c $< -o $@

# targets for each object file
$(foreach obj_file,$(OBJ_FILES),$(eval $(obj_file):))

# Install dependencies
install-dependencies:
	cat apt-packages.txt | sudo ./scripts/install-deps.sh

clean:
	rm -rf $(BUILD_DIR) $(TARGET) src/check*.c src/*.BAK src/*.NEW

####
# test running

TEST_RUN_OPTIONS = \
        export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1:abort_on_error=1:disable_core=0:disable_coredump=0"; \
        export ASAN_OPTIONS="detect_leaks=0:disable_core=0:unmap_shadow_on_exit=1:abort_on_error=1:disable_coredump=0"; export CK_VERBOSITY=verbose

TEST_SUITES = account_suite

# for debugging:
#test: SHELL=bash -x

test: $(TARGET)
	for suite in $(TEST_SUITES); do \
		$(TEST_RUN_OPTIONS); export CK_RUN_SUITE="$$suite"; ./$< ; \
	done

.PHONY: all clean

#.DELETE_ON_ERROR:

# Include automatically generated dependency files (.d)
-include $(OBJ_FILES:.o=.d)


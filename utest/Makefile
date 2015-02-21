# FIX THIS: This file should be a Makefile.in, and LIBS should be generated.
LIBS = -lcheck -lpthread -lm -lrt -lssl -lcrypto

SRCS = \
	test_base64.c \
	test_cmd.c \
	test_conf.c \
	test_hexmap.c \
	test_pathcmp.c

PROGS = clean $(SRCS:.c=.test)

.SUFFIXES:      .c .test

.c.test:
	@echo "Compiling $<"
	$(CXX) -Wall -g -o $@ $< ../src/$(subst test_,,$<) $(LIBS)
	@echo "Running $<"
	./$@ || exit 1
	rm $@
	@echo OK

test: ${PROGS}

clean:
	rm -vf *.test

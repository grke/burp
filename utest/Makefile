# FIX THIS: This file should be a Makefile.in, and LIBS should be generated.
LIBS = -lcheck -lpthread -lm -lrt -lssl

SRCS = \
	test_base64.c \
	test_cmd.c \
	test_hexmap.c \
	test_pathcmp.c

PROGS = clean $(SRCS:.c=.test)

.SUFFIXES:      .c .test

.c.test:
	@echo "Compiling $<"
	$(CXX) -Wall -o $@ $< ../src/$(subst test_,,$<) $(LIBS)
	@echo "Running $<"
	./$@ || exit 1
	rm $@
	@echo OK

test: ${PROGS}

clean:
	rm -vf *.test

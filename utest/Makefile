# FIX THIS: This file should be a Makefile.in, and LIBS should be generated.
LIBS = -lcheck -lpthread -lm -lrt -lssl -lcrypto

SRCS1 = \
	test_alloc.c \
	test_base64.c \
	test_cmd.c \
	test_hexmap.c \
	test_pathcmp.c

SRCS2 = \
	test_conf.c \

PROGS1 = clean $(SRCS1:.c=.test)
PROGS2 = clean $(SRCS2:.c=.test2)

.SUFFIXES:      .c .test .test2

.c.test:
	@echo "Compiling $<"
	$(CXX) -DUTEST -Wall -g -o $@ $< ../src/$(subst test_,,$<) $(LIBS)
	@echo "Running $<"
	./$@ || exit 1
	rm $@
	@echo OK

.c.test2:
	@echo "Compiling $<"
	$(CXX) -DUTEST -Wall -g -o $@ $< ../src/$(subst test_,,$<) ../src/alloc.c ../src/cntr.c ../src/prepend.c ../src/strlist.c $(LIBS)
	@echo "Running $<"
	./$@ || exit 1
	rm $@
	@echo OK

test: ${PROGS1} ${PROGS2}

clean:
	rm -vf *.test *.test2

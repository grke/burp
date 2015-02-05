LIBS = -lcheck -lpthread -lm -lrt

test: test_cmd test_pathcmp

test_cmd:
	$(CC) -o $@.test test_cmd.c ../src/cmd.c $(LIBS)
	./$@.test && rm $@.test

test_pathcmp:
	$(CC) -o $@.test test_pathcmp.c ../src/pathcmp.c $(LIBS)
	./$@.test && rm $@.test

clean:
	rm *.test

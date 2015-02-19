RM = /bin/rm
RMF = $(RM) -rf

clean:
	@$(RMF) build
	@$(RMF) logs
	@$(RMF) restore*
	@$(RMF) target
	@$(RMF) build.tar.bz2
	@$(RMF) clientscript
	@$(RMF) serverscript
	@$(RMF) windowsscript

test:
	make clean
	./test_self

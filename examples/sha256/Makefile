SYSROOT = --sysroot=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk

raw: sha256.ll test.c
	$(LLVM_HOME)/bin/clang -o sha256.raw sha256.ll test.c -Wall -pedantic $(SYSROOT) -g

sha256.ll.instrumented.ll: sha256.ll
	../../build/llvm-unroller sha256.ll sha256sum

sha256.ll: sha256.c
	$(LLVM_HOME)/bin/clang $(SYSROOT) sha256.c -c -S -emit-llvm -O3

sha256.tracer: sha256.ll.instrumented.ll test.c
	$(LLVM_HOME)/bin/clang -o $@ $^ -Wall -pedantic $(SYSROOT) -g

tracer.cpp: sha256.tracer
	./$^ > $@

tracer.out: tracer.cpp
	$(LLVM_HOME)/bin/clang++ -o $@ $^ -Wall -pedantic $(SYSROOT) -O2

clean:
	rm -rf *.ll *.dSYM sha256.raw sha256.tracer

SYSROOT = --sysroot=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk

raw.out: main.c kernel.c
	$(LLVM_HOME)/bin/clang -o $@ $^ -Wall -pedantic $(SYSROOT) -g -O3

kernel.ll: kernel.c
	$(LLVM_HOME)/bin/clang $(SYSROOT) $^ -c -S -emit-llvm -O1

kernel.ll.instrumented.ll: kernel.ll
	../../build/llvm-unroller kernel.ll sum100

sum100_trace.ll: trace_dumper.out
	./$^ > $@ 

trace.json: tracer.out
	./$^ > $@

tracer.out: kernel.ll.instrumented.ll main.c
	$(LLVM_HOME)/bin/clang -o $@ $^ -Wall -pedantic $(SYSROOT) -g

sum100_trace.ll: trace_dumper.out
	./$^

unrolled.out: main.c sum100_trace.ll
	$(LLVM_HOME)/bin/clang -o $@ $^ -Wall -pedantic $(SYSROOT) -g -O3

clean:
	rm -rf *.ll *.dSYM *.out trace_dumper.cpp

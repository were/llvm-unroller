.PHONY: build
build:
	cmake -B build -S . -DLLVM_HOME=$(LLVM_HOME) -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
	make -C build

clean:
	make -C build clean

ultraclean:
	rm -rf build

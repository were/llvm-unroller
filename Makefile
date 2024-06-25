.PHONY: build
build:
	cmake -B build -S .
	make -C build

clean:
	make -C build clean

ultraclean:
	rm -rf build

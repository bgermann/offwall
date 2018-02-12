CARGO=cross
TARGET=sparcv9-sun-solaris

offwall: build
	pkgmk -o -d . -f pkg/prototype

offwall.pkg: offwall
	pkgtrans . $@ $<

build:
	$(CARGO) build --release --all-features --target $(TARGET)

clean:
	$(CARGO) clean
	rm -rf offwall offwall.pkg

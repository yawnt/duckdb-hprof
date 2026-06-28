.PHONY: debug release clean

EXT_NAME = hprof

debug:
	cargo build
	mkdir -p build/debug
	cp target/debug/lib$(EXT_NAME).dylib build/debug/lib$(EXT_NAME).dylib
	python3 -c "import shutil;lib='build/debug/lib$(EXT_NAME).dylib';out='build/debug/$(EXT_NAME).duckdb_extension';shutil.copy(lib,out);p=lambda s:s.encode()[:32].ljust(32,b'\x00');open(out,'ab').write(b'\x00\x93\x04\x10duckdb_signature\x80\x04'+p('')+p('')+p('')+p('C_STRUCT_UNSTABLE')+p('0.1.0')+p('v1.5.4')+p('osx_arm64')+p('4')+b'\x00'*256)"

release:
	cargo build --release
	mkdir -p build/release
	cp target/release/lib$(EXT_NAME).dylib build/release/lib$(EXT_NAME).dylib
	python3 -c "import shutil;lib='build/release/lib$(EXT_NAME).dylib';out='build/release/$(EXT_NAME).duckdb_extension';shutil.copy(lib,out);p=lambda s:s.encode()[:32].ljust(32,b'\x00');open(out,'ab').write(b'\x00\x93\x04\x10duckdb_signature\x80\x04'+p('')+p('')+p('')+p('C_STRUCT_UNSTABLE')+p('0.1.0')+p('v1.5.4')+p('osx_arm64')+p('4')+b'\x00'*256)"

clean:
	rm -rf build target

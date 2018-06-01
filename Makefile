obj = core2ELF64 sample/hello/hello sample/hello_pie/hello \
	  sample/hello_full_relro/hello sample/minimal/hello \
	  sample/hello_static/hello sample/minimal_lib/hello \
	  sample/minimal_lib/func.o

all: $(obj)

core2ELF64: core2ELF64.c
	gcc core2ELF64.c -o core2ELF64	

sample/hello/hello: sample/hello/hello.c
	gcc sample/hello/hello.c -o sample/hello/hello

sample/hello_pie/hello: sample/hello_pie/hello.c
	gcc sample/hello_pie/hello.c -o sample/hello_pie/hello -fpie -pie

sample/hello_full_relro/hello: sample/hello_full_relro/hello.c
	gcc sample/hello_full_relro/hello.c -o sample/hello_full_relro/hello \
	-D_FORTIFY_SOURCE=2 -fstack-protector --param ssp-buffer-size=4 -fPIE -pie \
	-Wl,-z,relro,-z,now

sample/hello_static/hello: sample/hello_static/hello.c
	gcc sample/hello_static/hello.c -o sample/hello_static/hello -static

sample/minimal/hello: sample/minimal/hello.c
	gcc sample/minimal/hello.c -o sample/minimal/hello --static -nostdlib

sample/minimal_lib/func.o: sample/minimal_lib/func.c sample/minimal_lib/func.h
	gcc -c sample/minimal_lib/func.c -o sample/minimal_lib/func.o -Isample/minimal_lib

sample/minimal_lib/hello: sample/minimal/hello.c sample/minimal_lib/func.o
	ar rcs sample/minimal_lib/func.a sample/minimal_lib/func.o
	gcc sample/minimal_lib/hello.c -o sample/minimal_lib/hello --static -nostdlib \
		-I sample/minimal_lib/ sample/minimal_lib/func.a

clean:
	rm -f $(obj) sample/minimal_lib/func.a

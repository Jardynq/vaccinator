# vaccinator

This is a proof of concept recursive manual mapping image injector.
This contains a lot of research on how the windows exe loader.
The idea behind this injector is to fully implement an image loader that compiles to shellcode that can be injected.
It contains no winapi calls, only direct syscalls that are inlined (see [nt syscall](https://github.com/Jardynq/nt-syscall-rs))

As an extra challenge, this is written in pure rust. Proving that rust is a suitable language for low level hacky programming for security research. 
Personally i like writing in rust a lot more than something like c++, since the envirenment allows for much better metaprogramming and gives more (easier) control over compilation, since there isn't 100 different compilers with different implementations

Using this image injector makes it really easy to append [heavens gate](http://blog.rewolf.pl/blog/?p=102) and allow for code architechture mixing.

This injector is expected to: <br/>
inject any image (dll, exe, maybe even C# IL) <br/>
Inject x86 image -> x64 app <br/>
Inject x64 image -> x86 app <br/>
Inject image into app with same architecture

It will be able to run on windows 32bit, 64bit and 32bit emulated (WoW64)

Current biggest issue is user32.dll, since it uses gdi which is inside of the kernel. That makes it really hard to debug and reverse engineer how it's being loaded and why it's failing.

I might make a full writeup on all the resaerch, ideas and issues that were encountered in development.
# vaccinator

This is a proof of concept recursive manual mapping image injector.
This contains a lot of research on how the windows exe loader works.
The idea behind this injector is to fully implement an image loader, that compiles to shellcode which can be injected.
It contains no winapi calls, only direct assembly syscalls that are inlined (see [nt syscall](https://github.com/Jardynq/nt-syscall-rs))

As an extra challenge, this is written in pure rust (with inline asm). Proving that rust is a suitable language for low level hacky programming for security research. 
Personally, i like writing in rust a lot more than something like c++, since the environment allows for much better metaprogramming and gives more (easier) control over compilation, since there isn't 100 different compilers with different implementations.

Using this image injector makes it really easy to append [heavens gate](http://blog.rewolf.pl/blog/?p=102) that allows code architecture mixing.

This injector is expected to: <br/>
inject any image (dll, exe, maybe even C# IL) <br/>
Inject x86 image -> x64 app <br/>
Inject x64 image -> x86 app <br/>
Inject image -> app with same architecture

It will be able to run on windows 32bit, 64bit and 32bit emulated (WoW64)

Current biggest issue is user32.dll, since it uses gdi which is inside of the kernel. That makes it really hard to debug and reverse engineer how it's being loaded and why it's failing. If it injects into a program that already has user32.dll loaded (using system loader), then this loader will simply grab a handle to that image and everything will work fine.

There is also a small caveat in loading this way. It does not add the images to the application's loaded dll list, which means that it can't be discovered by ordinary winapi calls. So if a dll depends on another dll, but grabs it dynamically using GetModuleHandle, then it will fail.
A possible solution to this, is to whitelist the images that are required to be added the the list.

I might make a full writeup on all the resaerch, ideas and issues that were encountered in development.

## Project structue

Extracter - A simple program that walks the export table of the input exe, finds the bodies of the supplied functions and copies the binary into a seperate file.
This is used in tandem with the loader, which compiles to a dll whereafter the extracter extracts the shellcode.

Interface - The definitions for all the code used by the loader. This is used as a shared interface that will allow an injector to pass the correct data to the loader.

Loader - The code that is injected, and does the loading. The code is directly copied into a different program which means, that the code cannot contain absolute pointers. Everything has to be on the stack. For this, a lot of macros_rules! are used, since they are effectly functions that are inlined.

Test - Sample dlls and program, sued for debugging and testing. Dummy is a very simple image, that does nothing. Image is an image that creates a message box with some info about the program and itself. Program is a simple program that runs in a loop. Used for injecting into.

Src - The injector itself. It reads the binary shellcode that the extractor read from the loader, aswell as the image binary itself. Then writes it into the target process. Finally creates (or hijacks) a thread to start running the loader. 

Shared - A directory where all the binaries are pasted, so that the loader does not have to delve into ./target/


## Compilation and usage
I use [cargo-make](https://github.com/sagiegurari/cargo-make) as a build script. Look at MakeFile.toml for more info.<br/>
To build and prepare the loader use 'cargo make extract', this will compile and extract the loader.<br/>
To build and prepare the test dummies use 'cargo make share' or 'cargo make share-test'<br/>
To run the injector itself use 'cargo run'.<br/>

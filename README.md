# friis
Process injection malware using reflective DLL injection and stack spoofing, written in Go.

## Build Process
This project was designed to be built on Linux and used on Windows targets. However, you could easily integrate the DLL build process into Visual Studio.
```bash
make clean && make all
```

Docker image for base cases to be used within the QA pipeline.
```bash
docker build -t .
```

## Technical Information
This program works by injecting the locally compiled DLL under payloads, into a running process and executing it. It does this using `go generate` and `go build` to statically integrate the shellcode into the injector (this means it is an unstaged virus).

The main function, simply generates/locates a process to inject into, reflectively maps the DLL into that process' memory, and terminates after executing the DLL's `.text` section.
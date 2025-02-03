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
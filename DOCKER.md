# Building Docker Images

This document explains how to build Docker images for the gcEVM node project.

## Prerequisites

- Docker installed and running on your system
- Sufficient disk space for building images (several GB may be required)

## Available Dockerfiles

This project contains several Dockerfiles for different use cases:

1. **`Dockerfile.geth-installs`** - Base image with Ubuntu 22.04 and build dependencies (OpenSSL, build tools, etc.)
2. **`Dockerfile.general-node-rpc`** - Main production image with geth built from source, includes MPC support.
3. **`Dockerfile`** - Standard geth image built with Alpine Linux
4. **`Dockerfile.alltools`** - Image containing all geth tools built with Alpine Linux

Only the first two files are needed to create a production-ready geth node with MPC.

## Building the General Node RPC Image

The `Dockerfile.general-node-rpc` is a multi-stage build that creates a production-ready geth node with MPC. This requires building the base image first.

### Step 1: Build the Base Image

First, build the `geth-installs` base image:

```bash
docker build -f Dockerfile.geth-installs -t geth-installs:latest .
```

This creates a base image with:
- Ubuntu 22.04
- Build essentials
- OpenSSL 3.0.2
- libssl-dev and libspdlog-dev

### Step 2: Build the Main Image

Once the base image is built, create the main geth node image:

```bash
docker build -f Dockerfile.general-node-rpc -t gcEVM-node:latest .
```

This will:
- Build geth from the local source code
- Include the SES shared library (`libses.so`) and header files
- Create a production-ready image with geth binary and required dependencies
- Expose ports: 8545 (HTTP-RPC), 8546 (WS-RPC), 6002, 30303 (P2P), and 30303/udp

### Complete Build Command (One-liner)

You can build both images in sequence:

```bash
docker build -f Dockerfile.geth-installs -t geth-installs:latest . && \
docker build -f Dockerfile.general-node-rpc -t gcEVM-node:latest .
```

# Base Image
FROM ubuntu:24.04

LABEL version="0.9"
LABEL description="Secure Decoder with MbedTLS for MAX78000FTHR"

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /root

# Install Required Dependencies
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    gcc-arm-none-eabi \
    libnewlib-arm-none-eabi \
    make \
    git \
    wget \
    unzip \
    cmake \
    ninja-build \
    python3 \
    python3-pip \
    libssl-dev \
    python3-venv \
    clang \
    gcc \
    g++ \
    pkg-config

# Clone & Build MbedTLS for ARM Cortex-M4
RUN git clone --depth=1 https://github.com/Mbed-TLS/mbedtls.git /root/mbedtls && \
    cd /root/mbedtls && \
    mkdir build && cd build && \
    cmake -DUSE_SHARED_MBEDTLS_LIBRARY=ON -DCMAKE_BUILD_TYPE=Release .. && \
    make -j$(nproc) && make install

# Set Environment Variable for Maxim SDK
ENV MAXIM_PATH=/root/msdk-2024_02

# Clone & Set Up Maxim SDK for MAX78000
RUN git clone --recursive https://github.com/MaximIntegratedMSDK/msdk.git $MAXIM_PATH

# Create Working Directory for Decoder
WORKDIR /decoder

# Copy Decoder Source Files & SimpleCrypto Library
COPY decoder.c .
COPY simple_crypto.h .
COPY simple_crypto.c .
COPY gen_secrets.py .
COPY gen_subscription.py .

# Install Python Dependencies
RUN python3 -m venv /root/venv && \
    /root/venv/bin/pip install --upgrade pip && \
    /root/venv/bin/pip install cryptography loguru

# Ensure Python Virtual Environment Is Activated
ENV PATH="/root/venv/bin:$PATH"

# Compile the Decoder for MAX78000FTHR
RUN arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -O2 -o decoder.elf \
    decoder.c simple_crypto.c \
    -I/root/mbedtls/include \
    -L/root/mbedtls/library -lmbedtls -lmbedcrypto -lmbedx509 \
    -T${MAXIM_PATH}/Tools/ARM/GCC/gcc_arm.ld

# Convert ELF to Binary for Flashing
RUN arm-none-eabi-objcopy -O binary decoder.elf decoder.bin

# Set Default Entry Command to Copy Output
ENTRYPOINT ["bash", "-c", "cp decoder.bin /out"]

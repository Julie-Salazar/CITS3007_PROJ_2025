FROM ubuntu:22.04

# Set non-interactive mode for apt
ENV DEBIAN_FRONTEND=noninteractive

# Basic development tools
RUN apt update && \
    apt install -y curl git sudo build-essential && \
    apt clean

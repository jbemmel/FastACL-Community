FROM ubuntu:24.04

ARG VPP_REPO=2510
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential cmake ninja-build git curl ca-certificates gnupg \
       python3 python3-ply libnl-3-dev libnl-genl-3-dev gdb sudo \
    && curl -fsSL "https://packagecloud.io/fdio/${VPP_REPO}/gpgkey" \
       | gpg --dearmor -o /usr/share/keyrings/fdio.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/fdio.gpg] https://packagecloud.io/fdio/${VPP_REPO}/ubuntu/ noble main" \
       > /etc/apt/sources.list.d/fdio.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends vpp-dev libvppinfra-dev \
    && rm -rf /var/lib/apt/lists/*

# Ubuntu supplies a UID 1000 user; reuse it for writable bind-mounted sources.
RUN usermod -l developer -d /home/developer -m ubuntu \
    && groupmod -n developer ubuntu \
    && echo 'developer ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/developer \
    && chmod 0440 /etc/sudoers.d/developer

USER developer
WORKDIR /workspaces/FastACL-Community
CMD ["bash"]

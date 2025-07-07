FROM debian:trixie-20250630
RUN apt-get update -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates

#########
##
## May need these 2 lines below as/when toolchain updates hit trixie
#RUN echo "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20240422T205059Z/ unstable main" > /etc/apt/sources.list
#RUN echo "deb-src [check-valid-until=no] https://snapshot.debian.org/archive/debian/20240422T205059Z/ unstable main" >> /etc/apt/sources.list
##
#########

RUN apt-get update -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential wget git

RUN git clone https://github.com/vyos/shim-review.git
WORKDIR /shim-review
RUN git checkout vyos-shim-16.0-amd64-20250707
WORKDIR /

# Download and verify the upstream source tarball for shim
RUN wget https://github.com/rhboot/shim/releases/download/16.0/shim-16.0.tar.bz2
RUN echo "d503f778dc75895d3130da07e2ff23d2393862f95b6cd3d24b10cbd4af847217  shim-16.0.tar.bz2" > SHA256SUM
RUN sha256sum -c < SHA256SUM

# Rename the tarball to match what our packaging tools look for
RUN mv shim-16.0.tar.bz2 shim_16.0.orig.tar.bz2
RUN git clone https://github.com/vyos/efi-boot-shim.git
WORKDIR /efi-boot-shim
RUN git checkout vyos/current
RUN apt-get build-dep -y .
RUN dpkg-buildpackage -us -uc
WORKDIR /
RUN hexdump -Cv /efi-boot-shim/shim*.efi > build
RUN hexdump -Cv /shim-review/$(basename /shim/shim*.efi) > orig
RUN diff -u orig build || (echo "Build verification failed!" && exit 1)
RUN sha256sum /efi-boot-shim/shim*.efi /shim-review/$(basename /shim/shim*.efi)

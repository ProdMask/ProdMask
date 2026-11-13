# The image GoReleaser builds at each release, from the binaries it has just
# built (dockers_v2 in .goreleaser.yaml). It isn't for docker build: its
# context is GoReleaser's, with one folder per platform.
#
# Alpine keeps a shell, so the image also works as a CI job image. It has no
# RUN step, so building the arm64 image needs no emulation. The base is a tag,
# not a digest, on purpose: each release picks up Alpine 3.24's latest fixes.
FROM alpine:3.24
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/prodmask /usr/local/bin/prodmask
USER 65532:65532
WORKDIR /work
ENTRYPOINT ["prodmask"]

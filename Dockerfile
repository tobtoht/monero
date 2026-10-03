FROM stagex/pallet-gcc-gnu-gnu:sx2026.09.0@sha256:7c3726b921c4478d6eb95ab73edca3e185bc710e61005f4cf661267816fda0da AS builder
COPY --from=stagex/core-curl:sx2026.09.0@sha256:c6da68f9257b13f640f8970c93e0363f1608f7d90b59a967177483a857e31044 . /
COPY --from=stagex/core-openssl:sx2026.09.0@sha256:f97827b11a98c010113e0d6acc464c77cbf6ea47a67867cfd1baff093bc5399a . /
COPY --from=stagex/core-ca-certificates:sx2026.09.0@sha256:90c35859632385f5db503e2f67bbc792da1676a70b6ec0d176df9215b3111187 . /
COPY --from=stagex/user-patch:sx2026.09.0@sha256:3ee30f7804a7531803b2f5f51dc224202f6cee6f1cda221c1693b7a389a423b6 . /
COPY --from=stagex/core-cmake:sx2026.09.0@sha256:5e18aebcf2e2fe80b2854e16034da0f2e45878087da68735d3270a9707d37c92 . /
COPY --from=stagex/core-ncurses:sx2026.09.0@sha256:a5875ef06637624ead593724c43ab27be5fc7dbec5d292022bfe234896f584c1 . /
COPY --from=stagex/pallet-rust:sx2026.09.0@sha256:6033fb215dd7c87c885dd7b1c12de42464606dcc0323fc57339318d61f010a30 . /

ENV TARGET="x86_64-pc-linux-musl"
WORKDIR /monero
COPY . .

RUN make -C contrib/depends -j$(nproc) download-linux NO_WALLET=1 NO_READLINE=1

RUN make -C contrib/depends -j$(nproc) HOST="${TARGET}" NO_WALLET=1 NO_READLINE=1

RUN cmake --toolchain "contrib/depends/${TARGET}/share/toolchain.cmake" -S . -B build \
        -DSTACK_TRACE=OFF \
        -DUSE_READLINE=OFF \
        -DUSE_DEVICE_TREZOR=OFF \
        -DSTATIC_FLAGS="-static-pie" && \
    cmake --build build --target daemon --parallel $(nproc)

FROM scratch

COPY --from=builder /monero/build/bin/monerod /

EXPOSE 18080
EXPOSE 18081

ENTRYPOINT ["/monerod"]
CMD ["--p2p-bind-ip=0.0.0.0", "--p2p-bind-port=18080", "--rpc-bind-ip=0.0.0.0", "--rpc-bind-port=18081", "--non-interactive", "--confirm-external-bind"]

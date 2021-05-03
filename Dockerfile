FROM debian:10.9

WORKDIR /opt
COPY . .

RUN apt update && apt install -y git make clang llvm libelf-dev pkg-config gcc g++-multilib
RUN git submodule update --init
RUN make

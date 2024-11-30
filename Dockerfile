FROM node:16 as builder
ADD ./frontend /frontend
WORKDIR /frontend
# RUN npm config set registry https://registry.npm.taobao.org
RUN npm config set fetch-timeout 800000
RUN npm cache verify
RUN npm install --legacy-peer-deps && npm run build

FROM ubuntu:18.04

# Deps
RUN apt-get update
RUN apt-get install -y z3 libz3-dev ghc cabal-install python-pip python-virtualenv
RUN rm -rf ~/.cabal/packages
RUN cabal update
RUN pip install ipaddr parsec==3.5 textx==1.8.0 Flask
RUN cabal --version
RUN ghc --version
RUN ghc --numeric-version
RUN ghc-pkg list base
RUN z3 --version

# Haskell libs
COPY ./lib/z3 /FWSlib/z3-haskell
WORKDIR /FWSlib/z3-haskell
RUN cabal install --global
COPY ./lib/HaPy /FWSlib/HaPy-haskell
WORKDIR /FWSlib/HaPy-haskell
RUN cabal install --global
COPY ./FireWallSynthesizer.cabal /FWS/
WORKDIR /FWS
RUN cabal install --global --dependencies-only

# Python libs
COPY ./lib/HaPy-python /FWSlib/HaPy-python
WORKDIR /FWSlib/HaPy-python
RUN python setup.py install

# FWS Build
COPY . /FWS
WORKDIR /FWS
RUN ./update_libs.sh
RUN cabal install --global

# Copy frontend data
COPY --from=builder /frontend/dist /FWS/fwsynthesizer/web/static
# Install python fws
RUN python setup.py install

# Entrypoint
WORKDIR /mnt
ENTRYPOINT ["fws"]

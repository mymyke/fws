.PHONY: repl clean

SANDBOX = cabal.sandbox.config

all: fws

venv:
	virtualenv --python=python2 venv/; \
	. venv/bin/activate; \
	pip install ipaddr parsec==3.5 textx==1.8.0 Flask hapy-ffi
	. venv/bin/activate; cd lib/HaPy-python; python setup.py install
	. venv/bin/activate; python setup.py install

$(SANDBOX): FireWallSynthesizer.cabal venv
	./update_libs.sh
	# rm -rf ~/.cabal/packages
	cabal update
	# cabal sandbox init --sandbox=venv/
	# cabal sandbox add-source lib/z3-haskell
	# cabal sandbox add-source lib/HaPy-haskell
	# cabal install --dependencies-only
	cabal v2-configure --allow-newer
	cabal v2-build lib:HaPy
	cabal v2-build lib:z3
	cabal v2-build FireWallSynthesizer
	# # cabal v2-install --overwrite-policy=always lib/z3-haskell
	# # cabal v2-install --overwrite-policy=always lib/HaPy-haskell
	

fws: $(SANDBOX) src/*.hs src/FWS/*.hs
	cabal install

repl: $(SANDBOX)
	cabal repl

clean:
	rm -fr lib/z3-haskell/dist
	rm -fr lib/HaPy-haskell/dist
	rm -fr lib/HaPy-python/build
	rm -fr build/
	cabal clean
	rm -fr venv/
	rm -f cabal.sandbox.config

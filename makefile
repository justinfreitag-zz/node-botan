make: all

all: waf test

waf:
	node-waf configure build

debug:
	node-waf configure --debug=true build

test:
	@mocha /test/node-botan-test.js

clean:
	@rm -rf ./build


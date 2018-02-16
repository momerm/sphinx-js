# Sphinx JS
The `sphinx-js` package implements the Sphinx mix packet format core cryptographic functions.

The paper describing sphinx may be found here:

George Danezis and Ian Goldberg. 
Sphinx: A Compact and Provably Secure Mix Format. IEEE Symposium on Security and Privacy 2009. 
http://www.cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf

## Usage
To use this package in another npm project install it as follows.
````
npm install git+https://github.com/momerm/sphinx-js.git --save
````
Then in your code you can require the following exports.
````
const SphinxParams = require("sphinx-js").SphinxParams;
const SC = require("sphinx-js").SphinxClient;
const sphinx_process = require("sphinx-js").SphinxNode.sphinx_process;
const Rand = require("sphinx-js").Rand;
````
To create browser code you will need to use Browserify.

For an example of how this library can be used please see the [sphinx-web](https://github.com/momerm/sphinx-web) project which implements a mock mix system.

## How to run tests
````
npm install --dev
npm test
````

## How to run the benchmarks
Run the node benchmark with 
````
npm install
npm benchmark
````
To run the browser benchmark first compile the browser code with Browserify. 
Then open `benchmark/browser/index.html` in your browser.
````
npm install --dev
grunt browserify
````

## Conformance testing
Sphinx-js was tested for compatibility with the [python implementation](https://github.com/momerm/sphinx).
If you require compatibility with the python implementation it is necessary to apply a small patch to the Milagro crypto library after install.
````
npm install --dev
grunt patch
````
The code for conformance testing is in the folder `ctest`. 
To make a test case run `node "make test.js"` which creates a file
`test case.json`. 
A test case consists of private keys of nodes and packet routed through those nodes.
The corresponding script, `ctest.js` checks if a test case can be processed correctly. Run it with `node ctest.js`.

The same programs exist in the python repository. 
Therefore conformance was tested by seeing if the test case produced by the python code was accepted the JS code and vice-versa.

## More information
Sphinx-js is a port of the [Sphinx python package](https://github.com/UCL-InfoSec/sphinx).
It is compatible with [this fork](https://github.com/momerm/sphinx)
of that package.

The Git repository for sphinx-js may be found at: https://github.com/momerm/sphinx-js

Sphinx-js uses the [Milagro Crypto JavaScript](https://github.com/milagro-crypto/milagro-crypto-js) cryptographic library.
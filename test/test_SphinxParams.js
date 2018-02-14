/*
Copyright 2011 Ian Goldberg
Copyright 2016 George Danezis (UCL InfoSec Group)
Copyright 2018 Omer Mirza

This file is part of Sphinx.

Sphinx is free software: you can redistribute it and/or modify
it under the terms of version 3 of the GNU Lesser General Public
License as published by the Free Software Foundation.

Sphinx is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with Sphinx.  If not, see
<http://www.gnu.org/licenses/>.

The LIONESS implementation and the xcounter CTR mode class are adapted
from "Experimental implementation of the sphinx cryptographic mix
packet format by George Danezis".
*/

const assert = require('chai').assert;
const SphinxParams = require("../lib/SphinxParams");
const getRandomValues = require('get-random-values');
const bytesjs = require("bytes.js");

describe("Test SphinxParams", function () {
    let params, k;

    before(function () {
        params = new SphinxParams();
        let rand = new Uint8Array(16);
        getRandomValues(rand);
        k = Array.from(rand);
    });

    it("test AES", function () {
        let m = "Hello World!"*7;
        let c = params.aes_ctr(k, bytesjs.fromString(m));
        let m2 = bytesjs.toString(params.aes_ctr(k, c));
        assert.strictEqual(m2, m);
    });

    it("test LIONESS", function () {
        let m = "ARG".repeat(16);
        let c = params.lioness_enc(k, bytesjs.fromString(m));
        let m2 = bytesjs.toString(params.lioness_dec(k, c));
        assert.strictEqual(m2, m);
    });

});
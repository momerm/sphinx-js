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
const Group_ECC = require("../lib/Group_ECC");
const Packer = require("../lib/Packer");

describe("Test Packer", function() {

    it("test encoding an ECP", function () {
        let G = new Group_ECC();
        let sec = G.gensecret();
        let gen = G.g;
        let alpha = G.expon(gen, sec);
        let packer = new Packer(G.ctx);
        let enc = packer.encode(alpha);
        let alpha_dec = packer.decode(enc);

        assert.isTrue(alpha.equals(alpha_dec));
    });

    it("test encoding an invalid public key", function () {
        let G = new Group_ECC();
        let alpha = new G.ctx.ECP();
        alpha.inf();
        let packer = new Packer(G.ctx);
        let enc = packer.encode(alpha);
        assert.throw(function () {
            packer.decode(enc);
        });
    });

});
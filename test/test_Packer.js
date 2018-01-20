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
const Packer = require("../lib/Packer");
const SphinxParams = require("../lib/SphinxParams");

describe("Test Packer", function () {
    let params = new SphinxParams();
    let ctx = params.group.ctx;
    let packer = new Packer(ctx);

   it("test encoding basic types", function () {
       let array = [[64, 128], "bob"];
       let buffer = packer.encode(array);
       let array2 = packer.decode(buffer);
       assert.deepEqual(array2, array);
   });

    it("test encoding a BIG", function () {
        let r = params.group.order;
        let buffer = packer.encode(r);
        let r2 = packer.decode(buffer);
        assert.instanceOf(r2, ctx.BIG);
        assert.strictEqual(r2, r);
    });

    it("test encoding an ECP", function () {
        let r = params.group.g;
        let buffer = packer.encode(r);
        let r2 = packer.decode(buffer);
        assert.instanceOf(r2, ctx.ECP);
        assert.deepEqual(r2, r);
    });

});
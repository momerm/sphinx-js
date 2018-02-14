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

describe("Test Group_ECC", function() {

    it("test group operations", function () {
        let G = new Group_ECC();
        let sec1 = G.gensecret();
        let sec2 = G.gensecret();
        let gen = G.g;

        assert(G.expon(G.expon(gen, sec1), sec2).equals(G.expon(G.expon(gen, sec2), sec1)));
        assert(G.expon(G.expon(gen, sec1), sec2).equals(G.multiexpon(gen, [sec2, sec1])));
    });

});
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
const sphinx_process = require("../lib/SphinxNode").sphinx_process;
const SC = require("../lib/SphinxClient");
const SphinxParams = require("../lib/SphinxParams");
const bytesjs = require("bytes.js");

describe("Test Sphinx Node", function() {
    let pki, params, use_nodes, nodes_routing, node_keys;

    before('initialise test fixtures', function (done) {
        let r = 5; // Number of nodes to use for routing.
        params = new SphinxParams();

        // The minimal PKI involves names of nodes and keys
        pki = {};
        for(let nid = 0; nid < 10; nid++) {
            let x = params.group.gensecret();
            let y = params.group.expon(params.group.g, x);
            pki[nid] = new SC.Pki_entry(nid, x, y);
        }

        // The simplest path selection algorithm and message packaging
        use_nodes = SC.rand_subset(Object.getOwnPropertyNames(pki), r);
        nodes_routing = use_nodes.map(n => SC.nenc(n));
        node_keys = use_nodes.map(n => pki[n].y);
        done();
    });

    it("test associated data length mismatch", function () {
        params.assoc_len = 4;
        let assoc_data = bytesjs.fromString("XXXX");
        let assoc = new Array(nodes_routing.length).fill(assoc_data);
        let header, delta;
        let dest = bytesjs.fromString("dest");
        let message = bytesjs.fromString("this is a test");
        [header, delta] = SC.create_forward_message(params, nodes_routing, node_keys, dest, message, assoc);
        let x = pki[use_nodes[0]].x;
        assert.throw(function() {sphinx_process(params, x, header, delta, assoc_data.slice(0,3));},
            "Associated data length mismatch: expected 4 and got 3.");
        params.assoc_len = 0;
    });

    it("test MAC mismatch", function () {
        let dest = bytesjs.fromString("dest");
        let message = bytesjs.fromString("this is a test");
        let [header, delta] = SC.create_forward_message(params, nodes_routing, node_keys, dest, message);
        let x = pki[use_nodes[0]].x;
        header[2][0] = 255 - header[2][0];
        assert.throw(function() {sphinx_process(params, x, header, delta);},
            "MAC mismatch.");
        params.assoc_len = 0;
    });

});

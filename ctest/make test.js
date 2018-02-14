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

/* Make a test case.
   The test case is a json file containing private keys of nodes and a sphinx packet routed through those nodes.
 */

const SphinxParams = require("../lib/SphinxParams");
const SC = require("../lib/SphinxClient");
const bytesjs = require("bytes.js");
const fs = require("fs");

const r = 5;
const params = new SphinxParams();

let nodes_routing = [];
let node_priv_keys = [];
let node_pub_keys = [];

for(let i = 0; i < r; i++) {
    let nid = "node" + i;
    let x = params.group.gensecret();
    let y = params.group.expon(params.group.g, x);

    nodes_routing.push(SC.nenc(nid));
    node_priv_keys.push(x);
    node_pub_keys.push(y);
}

let dest = bytesjs.fromString("bob");
let message = bytesjs.fromString("this is a test");
let [header, delta] = SC.create_forward_message(params, nodes_routing, node_pub_keys, dest, message);
let bin_message = SC.pack_message(params, [header, delta]);

// Save private keys and binary message to file
let enc_priv_keys = [];
for(let i = 0; i < r; i++) {
    let buf = [];
    node_priv_keys[i].toBytes(buf);
    enc_priv_keys.push(buf);
}

let testcase = {
    keys: enc_priv_keys,
    packet: Array.from(bin_message)
};

fs.writeFileSync("test case.json", JSON.stringify(testcase));
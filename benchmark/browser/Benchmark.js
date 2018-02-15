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

const SphinxParams = require("../../lib/SphinxParams");
const SC = require("../../lib/SphinxClient");
const sphinx_process = require("../../lib/SphinxNode").sphinx_process;

const bytesjs = require("bytes.js");
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
let t0, t1;


console.log("Testing message encoding time");
let header, delta;
let bin_message;
t0 = Date.now();

for(let i = 0; i < 100; i++) {
    [header, delta] = SC.create_forward_message(params, nodes_routing, node_pub_keys, dest, message);
    bin_message = SC.pack_message(params, [header, delta]);
}

t1 = Date.now();
let avgTime = (t1 - t0) / 100;
let text = `Encoding took ${avgTime} milliseconds.`;
console.log(text);
let para = document.createElement("p");
let node = document.createTextNode(text);
para.appendChild(node);
document.body.appendChild(para);


console.log("Testing message processing time");
let x = node_priv_keys[0];
let lens = JSON.stringify([params.max_len, params.m]);
let param_dict = {};
param_dict[lens] = params;
t0 = Date.now();

for(let i = 0; i < 100; i++) {
    [header, delta] = SC.unpack_message(param_dict, params.ctx, bin_message)[1];
    sphinx_process(params, x, header, delta);
}

t1 = Date.now();
avgTime = (t1 - t0) / 100;
text = `Processing took ${avgTime} milliseconds.`;
console.log(text);
para = document.createElement("p");
node = document.createTextNode(text);
para.appendChild(node);
document.body.appendChild(para);
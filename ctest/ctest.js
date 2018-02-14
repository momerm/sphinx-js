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

// See if the test case in the "test case.json" file can be processed correctly.

const fs = require('fs');
const SphinxParams = require("../lib/SphinxParams");
const SC = require("../lib/SphinxClient");
const sphinx_process = require("../lib/SphinxNode").sphinx_process;
const assert = require('assert');
const bytesjs = require("bytes.js");

function toHexString(byteArray) {
    return Array.from(byteArray, function(byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
}

const test_case = JSON.parse(fs.readFileSync('test case.json'));
const params = new SphinxParams();

let pki = {};
let use_nodes = [];

for(let i = 0; i < test_case['keys'].length; i++) {
    let nid = "node" + i;
    use_nodes.push(nid);
    console.log(nid);

    let x = params.ctx.BIG.fromBytes(test_case['keys'][i]);
    let y = params.group.expon(params.group.g, x);

    let buf = [];
    y.toBytes(buf);
    console.log(`Public key: ${toHexString(buf)}\n`);

    pki[nid] = new SC.Pki_entry(nid, x, y);
}

let lens = JSON.stringify([params.max_len, params.m]);
let param_dict = {};
param_dict[lens] = params;
let [px, [header, delta]] = SC.unpack_message(param_dict, params.ctx, Uint8Array.from(test_case['packet']));
assert(px === params);

console.log("Processing message by the sequence of mixes.");
let x = pki[use_nodes[0]].x;
let i = 0;
while (true) {
    let tag, B, mac_key;
    [tag, B, [header, delta], mac_key] = sphinx_process(params, x, header, delta);
    let routing = SC.route_unpack(B);

    console.log("round " + i);
    i++;

    if (routing[0] === SC.Relay_flag) {
        let addr = routing[1];
        x = pki[addr].x;
    }
    else if (routing[0] === SC.Dest_flag) {
        assert.strictEqual(routing.length, 1);
        let [dec_dest, dec_msg] = SC.receive_forward(params, mac_key, delta);
        console.log("\nMessage has reached its destination.");
        console.log(`To: ${bytesjs.toString(dec_dest)}`);
        console.log(`Message: ${bytesjs.toString(dec_msg)}`);
        break;
    }
    else {
        console.log("Error");
        assert(false);
        break;
    }
}
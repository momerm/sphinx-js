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
const SC = require("../lib/SphinxClient");
const Enc = require("../lib/EncodeString");
const sphinx_process = require("../lib/SphinxNode").sphinx_process;

describe("Test SphinxClient", function () {

   it("test routing messages", function () {
       let r = 5;
       let params = new SphinxParams();

       // The minimal PKI involves names of nodes and keys

       let pkiPriv = {};
       let pkiPub = {};

       for(let nid = 0; nid < 10; nid++) {
           let x = params.group.gensecret();
           let y = params.group.expon(params.group.g, x);
           pkiPriv[nid] = new SC.Pki_entry(nid, x, y);
           pkiPub[nid] = new SC.Pki_entry(nid, null, y);
       }

       // The simplest path selection algorithm and message packaging

       let use_nodes = SC.rand_subset(Object.getOwnPropertyNames(pkiPub), r);
       let nodes_routing = use_nodes.map(n => SC.nenc(n));
       let node_keys = use_nodes.map(n => pkiPub[n].y);
       let dest = Enc.stringtobytes("bob");
       let message = Enc.stringtobytes("this is a test");
       let [header, delta] = SC.create_forward_message(params, nodes_routing, node_keys, dest, message);

       // Test encoding and decoding

       let bin_message = SC.pack_message(params, [header, delta]);
       let lens = JSON.stringify([params.max_len, params.m]);
       let param_dict = {};
       param_dict[lens] = params;

       let [px, [header1, delta1]] = SC.unpack_message(param_dict, bin_message);
       assert.strictEqual(px, params);
       assert.deepEqual(header1, header);
       assert.deepEqual(delta1, delta);

       // Process message by the sequence of mixes
       let x = pkiPriv[use_nodes[0]].x;

       let i = 0;
       while (true) {
           let tag, B;
           [tag, B, [header, delta]] = sphinx_process(params, x, header, delta);
           let routing = SC.route_unpack(B);

           console.log("round " + i);
           i++;

           if (routing[0] === SC.Relay_flag) {
               let addr = routing[1];
               x = pkiPriv[addr].x;
           }
           else if (routing[0] === SC.Dest_flag) {
               assert.isNull(routing[1]);
               for(let j = 0; j < 16; j++) {
                   assert.strictEqual(delta[j], 0);
               }
               let [dec_dest, dec_msg] = SC.receive_forward(params, delta);
               assert.strictEqual(Enc.bytestostring(dec_dest), Enc.bytestostring(dest));
               assert.strictEqual(Enc.bytestostring(dec_msg), Enc.bytestostring(message));
               break;
           }
           else {
               assert.isTrue(false, "Error");
               break;
           }
       }

       // Test the nym creation
       let [surbid, surbkeytuple, nymtuple] = SC.create_surb(params, nodes_routing, node_keys, Enc.stringtobytes("myself"));

       message = Enc.stringtobytes("This is a reply");
       [header, delta] = SC.package_surb(params, nymtuple, message);

       x = pkiPriv[use_nodes[0]].x;

       while (true) {
           let tag, B;
           [tag, B, [header, delta]] = sphinx_process(params, x, header, delta);
           let routing = SC.route_unpack(B);

           if (routing[0] === SC.Relay_flag) {
               let addr = routing[1];
               x = pkiPriv[addr].x;
           }
           else if (routing[0] === SC.Surb_flag) {
               let [flag, dest, myid] = routing;
               break;
           }
       }

       let received = SC.receive_surb(params, surbkeytuple, delta);
       assert.strictEqual(Enc.bytestostring(received), Enc.bytestostring(message));
   });

   it("test encoding and processing times", function () {
       let r = 5;
       let params = new SphinxParams();

       // The minimal PKI involves names of nodes and keys
       let pkiPriv = {};
       let pkiPub = {};

       for(let nid = 0; nid < 10; nid++) {
           let x = params.group.gensecret();
           let y = params.group.expon(params.group.g, x);
           pkiPriv[nid] = new SC.Pki_entry(nid, x, y);
           pkiPub[nid] = new SC.Pki_entry(nid, null, y);
       }

       let use_nodes = SC.rand_subset(Object.getOwnPropertyNames(pkiPub), r);
       let nodes_routing = use_nodes.map(n => SC.nenc(n));
       let node_keys = use_nodes.map(n => pkiPub[n].y);

       let header, delta;
       let dest = Enc.stringtobytes("dest");
       let message = Enc.stringtobytes("this is a test");
       console.time("mix encoding");
     //  for(let i = 0; i < 100; i++) {
           [header, delta] = SC.create_forward_message(params, nodes_routing, node_keys, dest, message);
       //}
       console.timeEnd("mix encoding");

       console.time("mix processing");
      // for(let i = 0; i < 100; i++) {
           let x = pkiPriv[use_nodes[0]].x;
           sphinx_process(params, x, header, delta);
      // }
       console.timeEnd("mix processing");
   });

});
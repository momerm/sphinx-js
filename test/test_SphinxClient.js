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
const bytesjs = require("bytes.js");
const SphinxParams = require("../lib/SphinxParams");
const SC = require("../lib/SphinxClient");
const sphinx_process = require("../lib/SphinxNode").sphinx_process;

describe("Test SphinxClient", function () {
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

    it("test encoding and decoding", function () {
        let dest = bytesjs.fromString("bob");
        let message = bytesjs.fromString("this is a test");
        let [header, delta] = SC.create_forward_message(params, nodes_routing, node_keys, dest, message);

        let bin_message = SC.pack_message(params, [header, delta]);
        let lens = JSON.stringify([params.max_len, params.m]);
        let param_dict = {};
        param_dict[lens] = params;

        let [px, [header1, delta1]] = SC.unpack_message(param_dict, params.ctx, bin_message);
        assert.strictEqual(px, params);
        assert.isTrue(header1[0].equals(header[0]));
        assert.deepEqual(header1[1], header[1]);
        assert.deepEqual(header1[2], header[2]);
        assert.deepEqual(delta1, delta);
    });

   it("test routing messages", function (done) {
       let dest = bytesjs.fromString("bob");
       let message = bytesjs.fromString("this is a test");
       let [header, delta] = SC.create_forward_message(params, nodes_routing, node_keys, dest, message);

       // Process message by the sequence of mixes
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
               assert.strictEqual(bytesjs.toString(dec_dest), bytesjs.toString(dest));
               assert.strictEqual(bytesjs.toString(dec_msg), bytesjs.toString(message));
               break;
           }
           else {
               assert.fail();
               break;
           }
       }
       done();
   });

   it("test SURB", function () {
       let [surbid, surbkeytuple, nymtuple] = SC.create_surb(params, nodes_routing, node_keys, bytesjs.fromString("myself"));
       let message = bytesjs.fromString("This is a reply");
       let [header, delta] = SC.package_surb(params, nymtuple, message);

       // Relay message through nodes
       let x = pki[use_nodes[0]].x;
       while (true) {
           let tag, B;
           [tag, B, [header, delta]] = sphinx_process(params, x, header, delta);
           let routing = SC.route_unpack(B);

           if (routing[0] === SC.Relay_flag) {
               let addr = routing[1];
               x = pki[addr].x;
           }
           else if (routing[0] === SC.Surb_flag) {
               let [flag, dest, myid] = routing;
               assert.deepEqual(myid, surbid);
               break;
           }
       }

       let received = SC.receive_surb(params, surbkeytuple, delta);
       assert.strictEqual(bytesjs.toString(received), bytesjs.toString(message));
   });

/*
   it("test encoding and processing times", function () {
       let header, delta;
       let dest = bytesjs.fromString("dest");
       let message = bytesjs.fromString("this is a test");

       console.time("mix encoding");
     //  for(let i = 0; i < 100; i++) {
           [header, delta] = SC.create_forward_message(params, nodes_routing, node_keys, dest, message);
       //}
       console.timeEnd("mix encoding");

       console.time("mix processing");
      // for(let i = 0; i < 100; i++) {
           let x = pki[use_nodes[0]].x;
           sphinx_process(params, x, header, delta);
      // }
       console.timeEnd("mix processing");
   });
*/
    it("test assoc routing", function (done) {
        params.assoc_len = 4;
        let dest = bytesjs.fromString("bob");
        let message = bytesjs.fromString("this is a test");
        let assoc_data = bytesjs.fromString("XXXX");
        let assoc = new Array(nodes_routing.length).fill(assoc_data);
        let [header, delta] = SC.create_forward_message(params, nodes_routing, node_keys, dest, message, assoc);

        // Process message by the sequence of mixes
        let x = pki[use_nodes[0]].x;
        let i = 0;
        while (true) {
            let tag, B, mac_key;
            [tag, B, [header, delta], mac_key] = sphinx_process(params, x, header, delta, assoc_data);
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
                assert.strictEqual(bytesjs.toString(dec_dest), bytesjs.toString(dest));
                assert.strictEqual(bytesjs.toString(dec_msg), bytesjs.toString(message));
                break;
            }
            else {
                assert.fail();
                break;
            }
        }
        done();
        params.assoc_len = 0;
    });

    it("test body too long", function () {
        let body = new Array(1023).fill(65);
        SC.pad_body(1024, body);

        body = new Array(1024).fill(65);
        assert.throw(function() {SC.pad_body(1024, body);});
    });

    it("test modified body", function () {
        let dest = bytesjs.fromString("bob");
        let message = bytesjs.fromString("this is a test");
        let [header, delta] = SC.create_forward_message(params, nodes_routing, node_keys, dest, message);

        // Process message by the sequence of mixes
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
                // Modify message
                delta[0] = 255 - delta[0];
                assert.throw(function() {SC.receive_forward(params, mac_key, delta);});
                break;
            }
            else {
                assert.fail();
                break;
            }
        }
    });

    it("test modified SURB", function () {
        // Test the nym creation
        let [surbid, surbkeytuple, nymtuple] = SC.create_surb(params, nodes_routing, node_keys, bytesjs.fromString("myself"));
        let message = bytesjs.fromString("This is a reply");
        let [header, delta] = SC.package_surb(params, nymtuple, message);

        // Relay message through nodes
        let x = pki[use_nodes[0]].x;
        while (true) {
            let tag, B;
            [tag, B, [header, delta]] = sphinx_process(params, x, header, delta);
            let routing = SC.route_unpack(B);

            if (routing[0] === SC.Relay_flag) {
                let addr = routing[1];
                x = pki[addr].x;
            }
            else if (routing[0] === SC.Surb_flag) {
                break;
            }
        }

        delta[0] = 255 - delta[0];
        assert.throw(function() {SC.receive_surb(params, surbkeytuple, delta);});
    });

    it("test no parameter settings", function () {
        let dest = bytesjs.fromString("bob");
        let message = bytesjs.fromString("this is a test");
        let [header, delta] = SC.create_forward_message(params, nodes_routing, node_keys, dest, message);
        let bin_message = SC.pack_message(params, [header, delta]);
        let lens = JSON.stringify([params.max_len - 1, params.m]);
        let param_dict = {};
        param_dict[lens] = params;
        assert.throw(function() {SC.unpack_message(param_dict, params.ctx, bin_message);});
    });

    it("test insufficient space for routing info", function () {
        let pki = {};
        for(let nid = 0; nid < 10; nid++) {
            let x = params.group.gensecret();
            let y = params.group.expon(params.group.g, x);
            pki["node" + nid] = new SC.Pki_entry("node" + nid, x, y);
        }

        let use_nodes = Object.getOwnPropertyNames(pki);
        let nodes_routing = use_nodes.map(n => SC.nenc(n));
        let node_keys = use_nodes.map(n => pki[n].y);

        let dest = bytesjs.fromString("bob");
        let message = bytesjs.fromString("this is a test");
        assert.throw(function() {SC.create_forward_message(params, nodes_routing, node_keys, dest, message);});
    });

});
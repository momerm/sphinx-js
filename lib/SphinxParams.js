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

const assert = require("assert");
const Group_ECC = require("../lib/Group_ECC");

class SphinxParams {

    constructor(header_len = 192, body_len = 1024, assoc_len=0) {
        this.assoc_len = assoc_len;
        this.max_len = header_len;
        this.m = body_len;
        this.k = 16; // Security parameter
        this.group = new Group_ECC();
        this.ctx = this.group.ctx;
    }

    /* Input is from an octet string M, output is to an octet string C.
       Output is truncated to the length of the input */
    aes_ctr(K, M, IV = null) {
        let a = new this.ctx.AES();
        let i, ipt, opt;
        let buff = new Array(16);
        let length = M.length;
        let r = length % 16;
        let C = new Array(length);
        a.init(this.ctx.AES.CTR16, K.length, K, IV);

        ipt = opt = 0;
        while(ipt < length - r) {
            for (i = 0; i < 16; i++) {
                buff[i] = M[ipt++];
            }
            a.encrypt(buff);
            for (i = 0; i < 16; i++)
                C[opt++] = buff[i];
        }
        if(r > 0) {
            for(i = 0; i < r; i++) {
                buff[i] = M[ipt++];
            }
            for (; i < 16; i++) {
                buff[i] = 0;
            }
            a.encrypt(buff);
            for (i = 0; i < r; i++)
                C[opt++] = buff[i];
        }
        a.end();
        return C;
    }

    lioness_enc(key, message) {
        assert(key.length === this.k);
        assert(message.length >= this.k * 2);

        // Round 1
        let k1 = this.hash(message.slice(this.k).concat(key).concat([49])).slice(0, this.k);
        let c = this.aes_ctr(key, message.slice(0, this.k), k1);
        let r1 = c.concat(message.slice(this.k));

        // Round 2
        c = this.aes_ctr(key, r1.slice(this.k), r1.slice(0, this.k));
        let r2 = r1.slice(0, this.k).concat(c);

        // Round 3
        let k3 = this.hash(r2.slice(this.k).concat(key).concat([51])).slice(0, this.k);
        c = this.aes_ctr(key, r2.slice(0, this.k), k3);
        let r3 = c.concat(r2.slice(this.k));

        // Round 4
        c = this.aes_ctr(key, r3.slice(this.k), r3.slice(0, this.k));
        let r4 = r3.slice(0, this.k).concat(c);

        return r4;
    }

    lioness_dec(key, message) {
        assert(key.length === this.k);
        assert(message.length >= this.k * 2);

        let r4 = message;
        let r4_short = r4.slice(0, this.k);
        let r4_long = r4.slice(this.k);

        // Round 4
        let r3_long = this.aes_ctr(key, r4_long, r4_short);
        let r3_short = r4_short;

        // Round 3
        let k2 = this.hash(r3_long.concat(key).concat([51])).slice(0, this.k);
        let r2_short = this.aes_ctr(key, r3_short, k2);
        let r2_long = r3_long;

        // Round 2
        let r1_long = this.aes_ctr(key, r2_long, r2_short);
        let r1_short = r2_short;

        // Round 1
        let k0 = this.hash(r1_long.concat(key).concat([49])).slice(0, this.k);
        let c = this.aes_ctr(key, r1_short, k0);
        let r0 = c.concat(r1_long);

        return  r0;
    }

    // AES-CTR operation
    xor_rho(key, plain) {
        assert(key.length === this.k);
        return this.aes_ctr(key, plain);
    }

    // The HMAC; key is of length k, output is of length k
    mu(key, data) {
        assert(key.length === this.k);
        let ecdh = this.ctx.ECDH;
        let mac = new Array(this.k);
        ecdh.HMAC(ecdh.SHA256, data, key, mac);
        return mac;
    }

    // The PRP; key is of length k, data is of length m
    pi(key, data) {
        assert(key.length === this.k);
        assert(data.length === this.m);
        return this.lioness_enc(key, data);
    }

    // The inverse PRP; key is of length k, data is of length m
    pii(key, data) {
        assert(key.length === this.k);
        assert(data.length === this.m);
        return this.lioness_dec(key, data);
    }

    // The various hashes
    hash(data) {
        let H = new this.ctx.HASH256();
        H.process_array(data);
        return H.hash();
    }

    get_aes_key(s) {
        // [97, 101, 115, 95, 107, 101, 121, 58] = "aes_key:"
        return this.hash([97, 101, 115, 95, 107, 101, 121, 58].concat(this.group.printable(s))).slice(0, this.k);
    }

    derive_key(k, flavor) {
        assert(k.length === this.k);
        assert(flavor.length === this.k);
        let iv = flavor;
        let m = Array(this.k).fill(0);
        return this.aes_ctr(k, m, iv);
    }

    // "Compute a hash of alpha and s to use as a blinding factor"
    hb(k) {
        // "hbhbhbhbhbhbhbhb" = [104, 98, 104, 98, 104, 98, 104, 98, 104, 98, 104, 98, 104, 98, 104, 98]
        let K = this.derive_key(k, [104, 98, 104, 98, 104, 98, 104, 98, 104, 98, 104, 98, 104, 98, 104, 98]);
        return this.group.makeexp(K);
    }

    // "Compute a hash of s to use as a key for the PRG rho"
    hrho(k) {
        // "hrhohrhohrhohrho" = [104, 114, 104, 111, 104, 114, 104, 111, 104, 114, 104, 111, 104, 114, 104, 111]
        return this.derive_key(k, [104, 114, 104, 111, 104, 114, 104, 111, 104, 114, 104, 111, 104, 114, 104, 111]);
    }

    // "Compute a hash of s to use as a key for the HMAC mu"
    hmu(k) {
        // "hmu:hmu:hmu:hmu:" = [104, 109, 117, 58, 104, 109, 117, 58, 104, 109, 117, 58, 104, 109, 117, 58]
        return this.derive_key(k, [104, 109, 117, 58, 104, 109, 117, 58, 104, 109, 117, 58, 104, 109, 117, 58]);
    }

    // "Compute a hash of s to use as a key for the PRP pi"
    hpi(k) {
        // "hpi:hpi:hpi:hpi:" = [104, 112, 105, 58, 104, 112, 105, 58, 104, 112, 105, 58, 104, 112, 105, 58]
        return this.derive_key(k, [104, 112, 105, 58, 104, 112, 105, 58, 104, 112, 105, 58, 104, 112, 105, 58]);
    }

    // "Compute a hash of s to use to see if we've seen s before"
    htau(k) {
        // "htauhtauhtauhtau" = [104, 116, 97, 117, 104, 116, 97, 117, 104, 116, 97, 117, 104, 116, 97, 117]
        return this.derive_key(k, [104, 116, 97, 117, 104, 116, 97, 117, 104, 116, 97, 117, 104, 116, 97, 117]);
    }
}

module.exports = SphinxParams;
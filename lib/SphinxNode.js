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
*/

let assert = require("assert");

/* The heart of a Sphinx server, that processes incoming messages.
   It takes a set of parameters, the secret of the server, and an incoming message header and body. Optionally
   some associated data may also be passed in to check their integrity. */
function sphinx_process(params, secret, header, delta, assoc=[]) {
    let p = params;
    let group = p.group;
    let [alpha, beta, gamma] = header;

    if(p.assoc_len !== assoc.length)
        throw `Associated data length mismatch: expected ${p.assoc_len} and got ${assoc.length}.`;

    // Compute the shared secret
    let s = group.expon(alpha, secret);
    let aes_s = p.get_aes_key(s);

    assert(beta.length === p.max_len - 32);
    let gamma2 = p.mu(p.hmu(aes_s), assoc.concat(beta));
    for(let i = 0; i < gamma.length; i++) {
        if(gamma[i] !== gamma2[i])
            throw "MAC mismatch.";
    }

    let beta_pad = beta.concat(Array(2 * p.max_len).fill(0));
    let B = p.xor_rho(p.hrho(aes_s), beta_pad);

    let length = B[0];
    let routing = B.slice(1,1+length);
    let rest = B.slice(1+length);

    let tag = p.htau(aes_s);
    let b = p.hb(aes_s);
    alpha = group.expon(alpha, b);
    gamma = rest.slice(0, p.k);
    beta = rest.slice(p.k, p.k + (p.max_len - 32));
    delta = p.pii(p.hpi(aes_s), delta);
    let mac_key = p.hpi(aes_s);

    return [tag, routing, [[alpha, beta, gamma], delta], mac_key];
}

module.exports = {
    sphinx_process: sphinx_process
};
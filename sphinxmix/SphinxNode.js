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

// Core Process function -- devoid of any chrome
function sphinx_process(params, secret, header, delta) {
    /* The heart of a Sphinx server, that processes incoming messages.
I      It takes a set of parameters, the secret of the server, and an incoming message header and body. */
    let p = params;
    let group = p.group;
    let [alpha, beta, gamma] = header;

    // Check that alpha is in the group
    if(!group.in_group(alpha))
        throw "Alpha not in Group.";

    // Compute the shared secret
    let s = group.expon(alpha, secret);
    let aes_s = p.get_aes_key(s);

    console.assert(beta.length === p.max_len - 32);
    //Console.log("B: \n%s" % hexlify(beta))

    let gamma2 = p.mu(p.hmu(aes_s), beta);
    for(let i = 0; i < gamma.length; i++) {
        if(gamma[i] !== gamma2[i])
            throw "MAC mismatch.";
    }

    let beta_pad = beta.concat(new Array(2 * p.max_len).fill(0));
    let B = p.xor_rho(p.hrho(aes_s), beta_pad);

    let length = B[0];
    let routing = B.slice(1,1+length);
    let rest = B.slice(1+length);

    let tag = p.htau(aes_s);
    let b = p.hb(alpha, aes_s);
    alpha = group.expon(alpha, b);
    gamma = rest.slice(0, p.k);
    beta = rest.slice(p.k, p.k + (p.max_len - 32));
    delta = p.pii(p.hpi(aes_s), delta);

    return [tag, routing, [[alpha, beta, gamma], delta]];
}
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

const assert = require("assert");
const msgpack = require("msgpack5")();
const Packer = require("../lib/Packer");
const getRandomValues = require('get-random-values');

// FLAGS

// Routing flag indicating message is to be relayed.
const Relay_flag = 0xF0;

// Routing flag indicating message is to be delivered.
const Dest_flag = 0xF1;

// Routing flag indicating surb reply is to be delivered.
const Surb_flag = 0xF2;

function Header_record(alpha, s, b, aes) {
    this.alpha = alpha;
    this.s = s;
    this.b = b;
    this.aes = aes;
}

// Create a helper object to store PKI information.
function Pki_entry(id, x, y) {
    this.id = id;
    this.x = x;
    this.y = y;
}

/* Pad a Sphinx message body.
Padding/unpadding of message bodies: a 0 bit, followed by as many 1 bits as it takes to fill it up. */
function pad_body(msgtotalsize, body) {

    if (msgtotalsize - body.length - 1 < 0)
        throw "Insufficient space for body";

    body = body.concat([0x7F].concat(Array(msgtotalsize - body.length - 1).fill(0xFF)));

    return body;
}

function unpad_body(body) {
    // Unpad a Sphinx message body.
    let l = body.length - 1;
    while (body[l] === 0xFF && l > 0) l--;
    return body[l] === 0x7F ? body.slice(0, l) : [];
}

// Prefix-free encoding/decoding of node names and destinations

// The encoding of mix names.
function nenc(idnum) {
    return route_pack([Relay_flag, idnum]);
}

// Prefix free encoder for commands received by mix or clients.
function route_pack(info) {

    return Array.from(msgpack.encode(info));
}

// Decoder of prefix free encoder for commands received by mix or clients.
function route_unpack(packed) {
    return Array.from(msgpack.decode(Uint8Array.from(packed)));
}

// Return a list of nu random elements of the given list (without replacement).
function rand_subset(lst, nu) {
    let rand = new Uint8Array(lst.length);
    getRandomValues(rand);

    // temporary array holds objects with position and sort-value
    let mapped = lst.map(function (el, i) {
        return {index: i, value: rand[i]};
    });

    // sort the mapped array by the sort-values
    mapped.sort(function(a, b) {
        if (a.value > b.value) {
            return 1;
        }
        if (a.value < b.value) {
            return -1;
        }
        return 0;
    });

    // extract first nu elements from the resulting order
    return mapped.slice(0, nu).map(function(el){
        return lst[el.index];
    });
}

// Internal function, creating a Sphinx header.
function create_header(params, nodelist, keys, dest, assoc = null) {
    let node_meta = Array(nodelist.length);
    for(let i = 0; i < node_meta.length; i++) {
        node_meta[i] = Array.from(nodelist[i]);
        node_meta[i].unshift(nodelist[i].length);
    }

    let p = params;
    let nu = nodelist.length;

    if(p.assoc_len <= 0)
        assoc = new Array(nu).fill([]);

    assert(assoc.length === nu);
    for(let i = 0; i < assoc.length; i++)
        assert(assoc[i].length === p.assoc_len);

    let final_routing = Array.from(dest);
    final_routing.unshift(dest.length);
    let len_meta = node_meta.slice(1).reduce((a, b) => a + b.length, 0);
    let random_pad_len = (p.max_len - 32) - len_meta - (nu-1)*p.k - final_routing.length;
    if(random_pad_len < 0)
        throw "Insufficient space for routing info";

    let blind_factor = p.group.gensecret();
    let asbtuples = [];

    for (let i = 0; i < keys.length; i++) {
        let alpha = p.group.expon(p.group.g, blind_factor);
        let s = p.group.expon(keys[i], blind_factor);
        let aes_s = p.get_aes_key(s);
        let b = p.hb(aes_s);
        blind_factor = p.group.ctx.BIG.modmul(blind_factor, b, p.group.order);

        let hr = new Header_record(alpha, s, b, aes_s);
        asbtuples.push(hr);
    }

    // Compute the filler strings
    let phi = [];
    let min_len = p.max_len - 32;
    for (let i = 1; i < nu; i++) {
        let plain = phi.concat(Array(p.k + node_meta[i].length).fill(0));
        phi = p.xor_rho(p.hrho(asbtuples[i-1].aes), Array(min_len).fill(0).concat(plain));
        phi = phi.slice(min_len);
        min_len -= node_meta[i].length + p.k;
    }
    assert(phi.length ===  len_meta + (nu-1)*p.k);

    // Compute the (beta, gamma) tuples
    let rand = new Uint8Array(random_pad_len);
    getRandomValues(rand);
    let beta = final_routing.concat(Array.from(rand));
    beta = p.xor_rho(p.hrho(asbtuples[nu-1].aes), beta).concat(phi);
    let gamma = p.mu(p.hmu(asbtuples[nu-1].aes), assoc[nu-1].concat(beta));

    for(let i = nu-2; i > -1; i--) {
        let node_id = node_meta[i+1];
        let plain_beta_len = (p.max_len - 32) - p.k - node_id.length;
        let plain = node_id.concat(gamma).concat(beta.slice(0, plain_beta_len));
        beta = p.xor_rho(p.hrho(asbtuples[i].aes), plain);
        gamma = p.mu(p.hmu(asbtuples[i].aes), assoc[i].concat(beta));
    }

    return [[asbtuples[0].alpha, beta, gamma], asbtuples.map(el => el.aes)];
}

/*
Create a forward Sphinx message, ready to be processed by a first mix.
It takes as parameters a node list of mix information, that will be provided to each mix, forming the path of the
message; a list of public keys of all intermediate mixes; a destination and a message; and optionally an array of
associated data (byte arrays). */
function create_forward_message(params, nodelist, keys, dest, msg, assoc = null) {
    let p = params;
    let nu = nodelist.length;
    assert(dest.length < 128 && dest.length > 0);
    assert(p.k + 1 + dest.length + msg.length < p.m);

    // Compute the header and the secrets
    let final = route_pack([Dest_flag]);
    let [header, secrets] = create_header(params, nodelist, keys, final, assoc);

    // Create message body
    let payload = pad_body(p.m - p.k, Array.from(msgpack.encode([Uint8Array.from(dest), Uint8Array.from(msg)])));
    let mac = p.mu(p.hpi(secrets[nu-1]), payload);
    let body = mac.concat(payload);

    // Compute the delta values
    let delta = p.pi(p.hpi(secrets[nu-1]), body);
    for(let i = nu-2; i > -1; i--) {
        delta = p.pi(p.hpi(secrets[i]), delta);
    }

    return [header, delta];
}

/*
Creates a Sphinx single use reply block (SURB) using a set of parameters; a sequence of mix identifiers;
the corresponding keys of the mixes; and a final destination.
Returns:
    - A triplet [surbid, surbkeytuple, nymtuple] where the surbid can be used as an index to store the secrets,
    surbkeytuple; nymtuple is the actual SURB that needs to be sent to the receiver. */
function create_surb(params, nodelist, keys, dest, assoc=null) {
    let p = params;
    let rand = new Uint8Array(p.k);
    getRandomValues(rand);
    let xid = Array.from(rand);

    // Compute the header and the secrets
    let final = route_pack([Surb_flag, dest, xid]);
    let [header, secrets] = create_header(params, nodelist, keys, final, assoc);

    getRandomValues(rand);
    let ktilde = Array.from(rand);
    let keytuple = [ktilde].concat(secrets.map(s => p.hpi(s)));
    return [xid, keytuple, [nodelist[0], header, ktilde]];
}

/*
Packages a message to be sent with a SURB. The message has to be bytes, and the nymtuple is the structure returned by
create_surb(). Returns a header and a body to pass to the first mix. */
function package_surb(params, nymtuple, message) {
    let [n0, header0, ktilde] = nymtuple;
    message = pad_body(params.m - params.k, message);
    let mac = params.mu(ktilde, message);
    let body = params.pi(ktilde, mac.concat(message));
    return [header0, body];
}

// Decodes the body of a forward message.
function receive_forward(params, mac_key, delta) {
    let mac = delta.slice(0, params.k);
    let mac2 =  params.mu(mac_key, delta.slice(params.k));
    for(let i = 0; i < params.k; i++) {
        if(mac[i] !== mac2[i])
            throw "Modified Body";
    }
    delta = unpad_body(delta.slice(params.k));
    return Array.from(msgpack.decode(Uint8Array.from(delta)));
}

/*
Processes a SURB body to extract the reply. The keytuple was provided at the time of SURB creation, and can be indexed
by the SURB id, which is also returned to the receiving user. Returns the decoded message. */
function receive_surb(params, keytuple, delta) {
    let p = params;
    let ktilde = keytuple.shift();
    let nu = keytuple.length;

    for (let i = nu-1; i > -1; i--) {
        delta = p.pi(keytuple[i], delta);
    }
    delta = p.pii(ktilde, delta);

    let mac = delta.slice(0, p.k);
    let mac2 = p.mu(ktilde, delta.slice(p.k));
    for(let i = 0; i < p.k; i++) {
        if(mac[i] !== mac2[i])
            throw "Modified SURB Body";
    }
    return unpad_body(delta.slice(p.k));
}
// A method to pack mix messages.
function pack_message(params, m) {
    let lens = [params.max_len, params.m];
    let [[alpha, beta, gamma], delta] = m;
    // encode as typed array for compatibility with other platforms (python)
    let packer = new Packer(params.ctx);
    return packer.encode([lens, [[alpha,
            Uint8Array.from(beta),
            Uint8Array.from(gamma)],
            Uint8Array.from(delta)]]);
}

// A method to unpack mix messages.
function unpack_message(params_dict, ctx, m) {
    let packer = new Packer(ctx);
    let [lens, [[alpha, beta, gamma], delta]] = packer.decode(m);

    let l = JSON.stringify(lens);
    if (!params_dict.hasOwnProperty(l))
        throw "No parameter settings for: " + lens;

    return [params_dict[l], [[alpha, Array.from(beta), Array.from(gamma)], Array.from(delta)]];
}

module.exports = {
    Relay_flag: Relay_flag,
    Dest_flag: Dest_flag,
    Surb_flag: Surb_flag,
    Header_record : Header_record,
    Pki_entry: Pki_entry,
    pad_body: pad_body,
    unpad_body: unpad_body,
    nenc: nenc,
    route_pack: route_pack,
    route_unpack: route_unpack,
    rand_subset: rand_subset,
    create_header: create_header,
    create_forward_message: create_forward_message,
    create_surb: create_surb,
    package_surb: package_surb,
    receive_forward: receive_forward,
    receive_surb: receive_surb,
    pack_message: pack_message,
    unpack_message: unpack_message,
};
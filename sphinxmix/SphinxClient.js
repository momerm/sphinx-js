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

// FLAGS

// Routing flag indicating message is to be relayed.
const Relay_flag = 0xF0;

// Routing flag indicating message is to be delivered.
const Dest_flag = 0xF1;

// Routing flag indicating surb reply is to be delivered.
const Surb_flag = 0xF2;

// Padding/unpadding of message bodies: a 0 bit, followed by as many 1
// bits as it takes to fill it up

function Header_record(alpha, s, b, aes) {
    this.alpha = alpha;
    this.s = s;
    this.b = b;
    this.aes = aes;
}

// #: A helper named tuple to store PKI information.
function Pki_entry(id, x, y) {
    this.id = id;
    this.x = x;
    this.y = y;
}

function pad_body(msgtotalsize, body) {
    // Pad a Sphinx message body.
    body = body.concat([0x7F].concat(Array(msgtotalsize - body.length - 1).fill(0xFF)));

    if (msgtotalsize - body.length < 0)
        throw "Insufficient space for body";

    return body;
}

function unpad_body(body) {
    // Unpad a Sphinx message body.
    let l = body.length - 1;
    while (body[l] === 0xFF && l > 0) l--;
    return body[l] === 0x7F ? body.slice(0, l) : [];
}

// Prefix-free encoding/decoding of node names and destinations

// Sphinx nodes
function nenc(idnum) {
    // The encoding of mix names.
    return route_pack([Relay_flag, idnum]);
}

function route_pack(info) {
    return msgpack.encode(info);
}

// Decode the prefix-free encoding.  Return the type, value, and the remainder of the input string.
function route_unpack(packed) {
    // Decoder of prefix free encoder for commands received by mix or clients.
    //Console.assert(typeof packed === bytes);
    return msgpack.decode(packed);
}

function rand_subset(lst, nu) {
    // Return a list of nu random elements of the given list (without replacement).

    let rand = new Uint8Array(lst.length);
    window.crypto.getRandomValues(rand);

    // temporary array holds objects with position and sort-value
    let mapped = lst.map(function (el, i) {
        return {index: i, value: rand[i]};
    });

    // sorting the mapped array containing the reduced values
    mapped.sort(function(a, b) {
        if (a.value > b.value) {
            return 1;
        }
        if (a.value < b.value) {
            return -1;
        }
        return 0;
    });

    // container for the resulting order
    return mapped.slice(0, nu).map(function(el){
        return lst[el.index];
    });
}

function create_header(params, nodelist, keys, dest) {
    /* Internal function, creating a Sphinx header, given parameters, a node list (path),
    a pki mapping node names to keys, a destination, and a message identifier. */

    let node_meta = Array(nodelist.length);
    for(let i = 0; i < node_meta.length; i++) {
        node_meta[i] = Array.from(nodelist[i]);
        node_meta[i].unshift(nodelist[i].length);
    }

    let p = params;
    let nu = nodelist.length;
    let max_len = p.max_len;
    let group = p.group;

    let blind_factor = group.gensecret();
    let asbtuples = [];

    for (let i = 0; i < keys.length; i++) {
        let alpha = group.expon(group.g, blind_factor);
        let s = group.expon(keys[i], blind_factor);
        let aes_s = p.get_aes_key(s);

        let b = p.hb(aes_s);
        blind_factor = group.ctx.BIG.modmul(blind_factor, b, group.order);

        let hr = new Header_record(alpha, s, b, aes_s);
        asbtuples.push(hr);
    }

    // Compute the filler strings
    let phi = [];
    let min_len = max_len - 32;
    for (let i = 1; i < nu; i++) {
        let plain = phi.concat(Array(p.k + node_meta[i].length).fill(0));
        phi = p.xor_rho(p.hrho(asbtuples[i-1].aes), Array(min_len).fill(0).concat(plain));
        phi = phi.slice(min_len);

        min_len -= node_meta[i].length + p.k;
    }

    let len_meta = node_meta.slice(1).reduce((a, b) => a + b.length, 0);
    console.assert(phi.length ===  len_meta + (nu-1)*p.k);

    // Compute the (beta, gamma) tuples

    let final_routing = Array.from(dest);
    final_routing.unshift(dest.length);

    let random_pad_len = (max_len - 32) - len_meta - (nu-1)*p.k - final_routing.length;

    if(random_pad_len < 0) {
        throw "Insufficient space for routing info";
    }

    let rand = new Uint8Array(random_pad_len);
    window.crypto.getRandomValues(rand);

    let beta = final_routing.concat(Array.from(rand));
    beta = p.xor_rho(p.hrho(asbtuples[nu-1].aes), beta).concat(phi);

    let gamma = p.mu(p.hmu(asbtuples[nu-1].aes), beta);

    for(let i = nu-2; i > -1; i--) {
        let node_id = node_meta[i+1];

        let plain_beta_len = (max_len - 32) - p.k - node_id.length;

        let plain = node_id.concat(gamma).concat(beta.slice(0, plain_beta_len));

        beta = p.xor_rho(p.hrho(asbtuples[i].aes), plain);
        gamma = p.mu(p.hmu(asbtuples[i].aes), beta);
    }

    return [[asbtuples[0].alpha, beta, gamma], asbtuples.map(el => el.aes)];
}

function create_forward_message(params, nodelist, keys, dest, msg) {
    /* Creates a forward Sphix message, ready to be processed by a first mix.

    It takes as parameters a node list of mix information, that will be provided to each mix, forming the path of the message;
    a list of public keys of all intermediate mixes; a destination and a message (byte arrays). */

    let p = params;
    let nu = nodelist.length;
    console.assert(dest.length < 128 && dest.length > 0);
    console.assert(p.k + 1 + dest.length + msg.length < p.m);

    // Compute the header and the secrets

    let final = route_pack([Dest_flag, null]);
    let [header, secrets] = create_header(params, nodelist, keys, final);

    let body = pad_body(p.m, Array(p.k).fill(0).concat(Array.from(msgpack.encode([dest, msg]))));

    // Compute the delta values
    let delta = p.pi(p.hpi(secrets[nu-1]), body);
    for(let i = nu-2; i > -1; i--) {
        delta = p.pi(p.hpi(secrets[i]), delta);
    }

    return [header, delta];
}

function create_surb(params, nodelist, keys, dest) {
    /*
    Creates a Sphinx single use reply block (SURB) using a set of parameters;
        a sequence of mix identifiers; a pki mapping names of mixes to keys; and a final
        destination.

    Returns:
        - A triplet (surbid, surbkeytuple, nymtuple). Where the surbid can be
        used as an index to store the secrets surbkeytuple; nymtuple is the actual
        SURB that needs to be sent to the receiver.
    */
    let p = params;
    let rand = new Uint8Array(p.k);
    window.crypto.getRandomValues(rand);
    let xid = Array.from(rand);

    // Compute the header and the secrets
    let final = route_pack([Surb_flag, dest, xid]);
    let [header, secrets] = create_header(params, nodelist, keys, final);

    window.crypto.getRandomValues(rand);
    let ktilde = Array.from(rand);

    let keytuple = [ktilde].concat(secrets.map(s => p.hpi(s)));
    return [xid, keytuple, [nodelist[0], header, ktilde]];
}

function package_surb(params, nymtuple, message) {
    /*
    Packages a message to be sent with a SURB. The message has to be bytes,
    and the nymtuple is the structure returned by the create_surb call.

    Returns a header and a body to pass to the first mix.
    */
    let [n0, header0, ktilde] = nymtuple;
    let body = params.pi(ktilde, pad_body(params.m, Array(params.k).fill(0).concat(message)));
    return [header0, body];
}

function receive_forward(params, delta) {
    // Decodes the body of a forward message.

    for(let i = 0; i < params.k; i++) {
        if(delta[i] !== 0)
            throw "Modified Body";
    }

    delta = unpad_body(delta.slice(params.k));
    return msgpack.decode(delta);
}

function receive_surb(params, keytuple, delta) {
    /*
    Processes a SURB body to extract the reply. The keytuple was provided at the time of
    SURB creation, and can be indexed by the SURB id, which is also returned to the receiving user.
    Returns the decoded message.
    */
    let p = params;

    let ktilde = keytuple.shift();
    let nu = keytuple.length;

    for (let i = nu-1; i > -1; i--)
        delta = p.pi(keytuple[i], delta);
    delta = p.pii(ktilde, delta);

    for(let i = 0; i < p.k; i++) {
        if(delta[i] !== 0)
            return [];
    }

    return unpad_body(delta.slice(p.k));
}

function pack_message(params, m) {
    // A method to pack mix messages.
    // The general encoder in packer.js isn't working at the moment so have to do this manually.
    let lens = [params.max_len, params.m];
    let [[alpha, beta, gamma], delta] = m;
    let alpha_bytes = [];
    alpha.toBytes(alpha_bytes);
    return msgpack.encode([lens, [[alpha_bytes, beta, gamma], delta]]);
}

function unpack_message(params_dict, m) {
    // A method to unpack mix messages.
    // The general encoder in packer.js isn't working at the moment so have to do this manually.
    let [lens, [[alpha_bytes, beta, gamma], delta]] = msgpack.decode(m);

    let l = JSON.stringify(lens);
    if (!params_dict.hasOwnProperty(l))
        throw "No parameter settings for: " + lens;

    let params = params_dict[l];
    let alpha = params.group.ctx.ECP.fromBytes(alpha_bytes);
    return [params_dict[l], [[alpha, beta, gamma], delta]];
}
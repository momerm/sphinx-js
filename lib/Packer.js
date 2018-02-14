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

const msgpack = require("msgpack5")();

function Packer(ctx) {
    this.encodeECP = function (obj) {
        let bytes = [];
        obj.toBytes(bytes);
        return new Buffer(bytes);
    };

    this.decodeECP = function (data) {
        if(ctx.ECDH.PUBLIC_KEY_VALIDATE(data) === ctx.ECDH.INVALID_PUBLIC_KEY)
            throw "Invalid public key";

        return ctx.ECP.fromBytes(data);
    };

    msgpack.register(2, ctx.ECP, this.encodeECP, this.decodeECP);

    this.encode = function (obj) {
        return msgpack.encode(obj);
    };

    this.decode = function (data) {
        return msgpack.decode(data);
    };
}

module.exports = Packer;
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

const msgpack = require("msgpack-lite");

/* It would be nice if this worked. It isn't being used at the moment.
   My custom codecs are not getting called.
*/

function Packer(ctx) {
    this.ctx = ctx;

    this.myBIGpacker = function(big) {
        console.log("packing big");
        let bytes = new Uint8Array(big.MODBYTES);
        big.toBytes(bytes);
        return bytes;
    };

    this.myBIGunpacker = function(buffer) {
        console.log("unpacking big");
        return this.ctx.BIG.fromBytes(buffer);
    };

    this.myECPpacker = function(ecp) {
        console.log("packing ECP");
        let bytes = [];
        ecp.toBytes(bytes);
        return bytes;
    };

    this.myECPunpacker = function(buffer) {
        console.log("unpacking ECP");
        return this.ctx.ECP.fromBytes(buffer);
    };

    // My functions are not getting called
    this.codec = msgpack.createCodec({uint8array: true});
    this.codec.addExtPacker(0x3F, this.ctx.BIG, this.myBIGpacker);
    this.codec.addExtUnpacker(0x3F, this.myBIGunpacker);

    this.codec.addExtPacker(0x02, this.ctx.ECP, this.myECPpacker);
    this.codec.addExtUnpacker(0x02, this.myECPunpacker);

    this.encode = function (o) {
        return msgpack.encode(o, {codec : this.codec});
    };

    this.decode = function (buffer) {
        return msgpack.decode(buffer, {codec : this.codec});
    };
}

module.exports = Packer;


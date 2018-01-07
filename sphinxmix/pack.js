function stringtobytes(s) {
    // Assuming ASCII characters
    let b = new Array(s.length);
    for (let i = 0; i < s.length; i++)
        b[i] = s.charCodeAt(i);
    return b;
}

function bytestostring(b) {
    // Assuming ASCII characters
    let s = "";
    for(let i = 0; i < b.length; i++)
        s += String.fromCharCode(b[i]);
    return s;
}


function encode(o) {
    return stringtobytes(JSON.stringify(o));
}

function decode(b) {
    return JSON.parse(bytestostring(b))
}


function PACKER(ctx) {
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
        ecp.toBytes(b);
        return bytes;
    };

    this.myECPunpacker = function(buffer) {
        console.log("unpacking ECP");
        return this.ctx.ECP.fromBytes(buffer)
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
    }
}

// TEST
function test_packer() {
    let params = new SphinxParams();
    let ctx = params.group.ctx;
    let packer = new PACKER(ctx);

    // Test encoding basic types
    let array = [[64, 128], "bob"];
    let buffer = packer.encode(array);
    let array2 = packer.decode(buffer);

    console.assert(JSON.stringify(array) === JSON.stringify(array2));

    // Test encoding a BIG
    let r = params.group.order;
    buffer = packer.encode(r);
    let r2 = packer.decode(buffer);
    console.assert(ctx.BIG.comp(r, r2) === 0);

    // Test encoding an ECP
    r = params.group.g;
    buffer = packer.encode(r);
    r2 = packer.decode(buffer);
    console.assert(r.equals(r2));
}


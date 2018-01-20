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

const CTX = require("milagro-crypto-js");
const MyRand = require("../lib/MyRand");

function Group_ECC(gid = "C25519") {
    // Group operations in ECC
    this.ctx = new CTX(gid);

    // group generator
    let gx = new this.ctx.BIG(0);
    gx.rcopy(this.ctx.ROM_CURVE.CURVE_Gx);
    let gy = new this.ctx.BIG(0);
    gy.rcopy(this.ctx.ROM_CURVE.CURVE_Gy);
    this.g = new this.ctx.ECP(0);
    this.g.setxy(gx, gy);

    //group order
    this.order = new this.ctx.BIG(0);
    this.order.rcopy(this.ctx.ROM_CURVE.CURVE_Order);

    // Initialise random number generator
    this.rng = new MyRand();

    this.gensecret = function () {
        return this.ctx.BIG.randomnum(this.order, this.rng);
    };

    this.expon = function (base, exp) {
        return base.mul(exp);
    };

    this.multiexpon = function (base, exps) {
        let expon = new this.ctx.BIG(1);
        for (let i = 0; i < exps.length; i++) {
            expon = this.ctx.BIG.modmul(expon, exps[i], this.order);
        }
        return base.mul(expon);
    };

    this.makeexp = function (data) {
        let d = this.ctx.BIG.fromBytes(data);
        d.mod(this.order);
        return d;
    };

    this.in_group = function (alpha) {
        // All strings of length 32 are in the group, says DJB
        return true;
        // Verify that y^2 == x^3 + Ax^2 + x (mod p)
        /*
        let lhs = alpha.gety().sqr();
        let rhs = this.ctx.ECP.RHS(alpha.getx());
        return lhs.equals(rhs);
        */
    };

    this.printable = function(alpha) {
        return alpha.toString();
    };
}

module.exports = Group_ECC;
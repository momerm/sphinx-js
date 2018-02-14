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

const getRandomValues = require('get-random-values');

function Rand() {
    const POOL_LEN = 32;
    this.pool = new Uint8Array(POOL_LEN);
    this.pool_pos = POOL_LEN;

    this.getByte = function() {
        if(this.pool_pos === POOL_LEN) {
            getRandomValues(this.pool);
            this.pool_pos = 0;
        }

        return this.pool[this.pool_pos++];
    };
}

module.exports = Rand;
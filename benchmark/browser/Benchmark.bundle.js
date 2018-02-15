require=(function(){function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s}return e})()({"./aes":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

var AES = function() {
    "use strict";

    var AES = function() {
        this.Nk = 0;
        this.Nr = 0;
        this.mode = 0;
        this.fkey = [];
        this.rkey = [];
        this.f = [];
    };

    // AES constants
    AES.ECB = 0;
    AES.CBC = 1;
    AES.CFB1 = 2;
    AES.CFB2 = 3;
    AES.CFB4 = 5;
    AES.OFB1 = 14;
    AES.OFB2 = 15;
    AES.OFB4 = 17;
    AES.OFB8 = 21;
    AES.OFB16 = 29;
    AES.CTR1 = 30;
    AES.CTR2 = 31;
    AES.CTR4 = 33;
    AES.CTR8 = 37;
    AES.CTR16 = 45;

    AES.prototype = {
        /* reset cipher */
        reset: function(m, iv) { /* reset mode, or reset iv */
            var i;

            this.mode = m;

            for (i = 0; i < 16; i++) {
                this.f[i] = 0;
            }

            if (this.mode != AES.ECB && iv !== null) {
                for (i = 0; i < 16; i++) {
                    this.f[i] = iv[i];
                }
            }
        },

        getreg: function() {
            var ir = [],
                i;

            for (i = 0; i < 16; i++) {
                ir[i] = this.f[i];
            }

            return ir;
        },

        increment: function() {
            var i;

            for (i = 0; i < 16; i++) {
                this.f[i]++;

                if ((this.f[i] & 0xff) != 0) {
                    break;
                }
            }
        },

        /* Initialise cipher */
        init: function(m, nk, key, iv) { /* Key=16 bytes */
            /* Key Scheduler. Create expanded encryption key */
            var CipherKey = [],
                b = [],
                i, j, k, N, nr;

            nk /= 4;

            if (nk != 4 && nk != 6 && nk != 8) {
                return false;
            }

            nr = 6 + nk;

            this.Nk = nk;
            this.Nr = nr;


            this.reset(m, iv);
            N = 4 * (nr + 1);

            for (i = j = 0; i < nk; i++, j += 4) {
                for (k = 0; k < 4; k++) {
                    b[k] = key[j + k];
                }
                CipherKey[i] = AES.pack(b);
            }

            for (i = 0; i < nk; i++) {
                this.fkey[i] = CipherKey[i];
            }

            for (j = nk, k = 0; j < N; j += nk, k++) {
                this.fkey[j] = this.fkey[j - nk] ^ AES.SubByte(AES.ROTL24(this.fkey[j - 1])) ^ (AES.rco[k]) & 0xff;
                for (i = 1; i < nk && (i + j) < N; i++) {
                    this.fkey[i + j] = this.fkey[i + j - nk] ^ this.fkey[i + j - 1];
                }
            }

            /* now for the expanded decrypt key in reverse order */

            for (j = 0; j < 4; j++) {
                this.rkey[j + N - 4] = this.fkey[j];
            }

            for (i = 4; i < N - 4; i += 4) {
                k = N - 4 - i;
                for (j = 0; j < 4; j++) {
                    this.rkey[k + j] = AES.InvMixCol(this.fkey[i + j]);
                }
            }

            for (j = N - 4; j < N; j++) {
                this.rkey[j - N + 4] = this.fkey[j];
            }
        },

        /* Encrypt a single block */
        ecb_encrypt: function(buff) {
            var b = [],
                p = [],
                q = [],
                t, i, j, k;

            for (i = j = 0; i < 4; i++, j += 4) {
                for (k = 0; k < 4; k++) {
                    b[k] = buff[j + k];
                }
                p[i] = AES.pack(b);
                p[i] ^= this.fkey[i];
            }

            k = 4;

            /* State alternates between p and q */
            for (i = 1; i < this.Nr; i++) {
                q[0] = this.fkey[k] ^ AES.ftable[p[0] & 0xff] ^
                    AES.ROTL8(AES.ftable[(p[1] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.ftable[(p[2] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.ftable[(p[3] >>> 24) & 0xff]);
                q[1] = this.fkey[k + 1] ^ AES.ftable[p[1] & 0xff] ^
                    AES.ROTL8(AES.ftable[(p[2] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.ftable[(p[3] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.ftable[(p[0] >>> 24) & 0xff]);
                q[2] = this.fkey[k + 2] ^ AES.ftable[p[2] & 0xff] ^
                    AES.ROTL8(AES.ftable[(p[3] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.ftable[(p[0] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.ftable[(p[1] >>> 24) & 0xff]);
                q[3] = this.fkey[k + 3] ^ AES.ftable[p[3] & 0xff] ^
                    AES.ROTL8(AES.ftable[(p[0] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.ftable[(p[1] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.ftable[(p[2] >>> 24) & 0xff]);

                k += 4;
                for (j = 0; j < 4; j++) {
                    t = p[j];
                    p[j] = q[j];
                    q[j] = t;
                }
            }

            /* Last Round */

            q[0] = this.fkey[k] ^ (AES.fbsub[p[0] & 0xff] & 0xff) ^
                AES.ROTL8(AES.fbsub[(p[1] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.fbsub[(p[2] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.fbsub[(p[3] >>> 24) & 0xff] & 0xff);

            q[1] = this.fkey[k + 1] ^ (AES.fbsub[p[1] & 0xff] & 0xff) ^
                AES.ROTL8(AES.fbsub[(p[2] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.fbsub[(p[3] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.fbsub[(p[0] >>> 24) & 0xff] & 0xff);

            q[2] = this.fkey[k + 2] ^ (AES.fbsub[p[2] & 0xff] & 0xff) ^
                AES.ROTL8(AES.fbsub[(p[3] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.fbsub[(p[0] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.fbsub[(p[1] >>> 24) & 0xff] & 0xff);

            q[3] = this.fkey[k + 3] ^ (AES.fbsub[(p[3]) & 0xff] & 0xff) ^
                AES.ROTL8(AES.fbsub[(p[0] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.fbsub[(p[1] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.fbsub[(p[2] >>> 24) & 0xff] & 0xff);

            for (i = j = 0; i < 4; i++, j += 4) {
                b = AES.unpack(q[i]);
                for (k = 0; k < 4; k++) {
                    buff[j + k] = b[k];
                }
            }
        },

        /* Decrypt a single block */
        ecb_decrypt: function(buff) {
            var b = [],
                p = [],
                q = [],
                t, i, j, k;

            for (i = j = 0; i < 4; i++, j += 4) {
                for (k = 0; k < 4; k++) {
                    b[k] = buff[j + k];
                }
                p[i] = AES.pack(b);
                p[i] ^= this.rkey[i];
            }

            k = 4;

            /* State alternates between p and q */
            for (i = 1; i < this.Nr; i++) {
                q[0] = this.rkey[k] ^ AES.rtable[p[0] & 0xff] ^
                    AES.ROTL8(AES.rtable[(p[3] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.rtable[(p[2] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.rtable[(p[1] >>> 24) & 0xff]);
                q[1] = this.rkey[k + 1] ^ AES.rtable[p[1] & 0xff] ^
                    AES.ROTL8(AES.rtable[(p[0] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.rtable[(p[3] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.rtable[(p[2] >>> 24) & 0xff]);
                q[2] = this.rkey[k + 2] ^ AES.rtable[p[2] & 0xff] ^
                    AES.ROTL8(AES.rtable[(p[1] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.rtable[(p[0] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.rtable[(p[3] >>> 24) & 0xff]);
                q[3] = this.rkey[k + 3] ^ AES.rtable[p[3] & 0xff] ^
                    AES.ROTL8(AES.rtable[(p[2] >>> 8) & 0xff]) ^
                    AES.ROTL16(AES.rtable[(p[1] >>> 16) & 0xff]) ^
                    AES.ROTL24(AES.rtable[(p[0] >>> 24) & 0xff]);

                k += 4;

                for (j = 0; j < 4; j++) {
                    t = p[j];
                    p[j] = q[j];
                    q[j] = t;
                }
            }

            /* Last Round */

            q[0] = this.rkey[k] ^ (AES.rbsub[p[0] & 0xff] & 0xff) ^
                AES.ROTL8(AES.rbsub[(p[3] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.rbsub[(p[2] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.rbsub[(p[1] >>> 24) & 0xff] & 0xff);
            q[1] = this.rkey[k + 1] ^ (AES.rbsub[p[1] & 0xff] & 0xff) ^
                AES.ROTL8(AES.rbsub[(p[0] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.rbsub[(p[3] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.rbsub[(p[2] >>> 24) & 0xff] & 0xff);
            q[2] = this.rkey[k + 2] ^ (AES.rbsub[p[2] & 0xff] & 0xff) ^
                AES.ROTL8(AES.rbsub[(p[1] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.rbsub[(p[0] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.rbsub[(p[3] >>> 24) & 0xff] & 0xff);
            q[3] = this.rkey[k + 3] ^ (AES.rbsub[p[3] & 0xff] & 0xff) ^
                AES.ROTL8(AES.rbsub[(p[2] >>> 8) & 0xff] & 0xff) ^
                AES.ROTL16(AES.rbsub[(p[1] >>> 16) & 0xff] & 0xff) ^
                AES.ROTL24(AES.rbsub[(p[0] >>> 24) & 0xff] & 0xff);

            for (i = j = 0; i < 4; i++, j += 4) {
                b = AES.unpack(q[i]);
                for (k = 0; k < 4; k++) {
                    buff[j + k] = b[k];
                }
            }

        },

        /* Encrypt using selected mode of operation */
        encrypt: function(buff) {
            var st = [],
                bytes, fell_off, j;

            // Supported Modes of Operation

            fell_off = 0;

            switch (this.mode) {
                case AES.ECB:
                    this.ecb_encrypt(buff);
                    return 0;

                case AES.CBC:
                    for (j = 0; j < 16; j++) {
                        buff[j] ^= this.f[j];
                    }
                    this.ecb_encrypt(buff);
                    for (j = 0; j < 16; j++) {
                        this.f[j] = buff[j];
                    }
                    return 0;

                case AES.CFB1:
                case AES.CFB2:
                case AES.CFB4:
                    bytes = this.mode - AES.CFB1 + 1;
                    for (j = 0; j < bytes; j++) {
                        fell_off = (fell_off << 8) | this.f[j];
                    }
                    for (j = 0; j < 16; j++) {
                        st[j] = this.f[j];
                    }
                    for (j = bytes; j < 16; j++) {
                        this.f[j - bytes] = this.f[j];
                    }
                    this.ecb_encrypt(st);
                    for (j = 0; j < bytes; j++) {
                        buff[j] ^= st[j];
                        this.f[16 - bytes + j] = buff[j];
                    }
                    return fell_off;

                case AES.OFB1:
                case AES.OFB2:
                case AES.OFB4:
                case AES.OFB8:
                case AES.OFB16:
                    bytes = this.mode - AES.OFB1 + 1;
                    this.ecb_encrypt(this.f);
                    for (j = 0; j < bytes; j++) {
                        buff[j] ^= this.f[j];
                    }
                    return 0;

                case AES.CTR1:
                case AES.CTR2:
                case AES.CTR4:
                case AES.CTR8:
                case AES.CTR16:
                    bytes = this.mode - AES.CTR1 + 1;
                    for (j = 0; j < 16; j++) {
                        st[j] = this.f[j];
                    }
                    this.ecb_encrypt(st);
                    for (j = 0; j < bytes; j++) {
                        buff[j] ^= st[j];
                    }
                    this.increment();
                    return 0;

                default:
                    return 0;
            }
        },

        /* Decrypt using selected mode of operation */
        decrypt: function(buff) {
            var st = [],
                bytes,fell_off, j;

            // Supported modes of operation
            fell_off = 0;
            switch (this.mode) {
                case AES.ECB:
                    this.ecb_decrypt(buff);
                    return 0;

                case AES.CBC:
                    for (j = 0; j < 16; j++) {
                        st[j] = this.f[j];
                        this.f[j] = buff[j];
                    }
                    this.ecb_decrypt(buff);
                    for (j = 0; j < 16; j++) {
                        buff[j] ^= st[j];
                        st[j] = 0;
                    }
                    return 0;

                case AES.CFB1:
                case AES.CFB2:
                case AES.CFB4:
                    bytes = this.mode - AES.CFB1 + 1;
                    for (j = 0; j < bytes; j++) {
                        fell_off = (fell_off << 8) | this.f[j];
                    }
                    for (j = 0; j < 16; j++) {
                        st[j] = this.f[j];
                    }
                    for (j = bytes; j < 16; j++) {
                        this.f[j - bytes] = this.f[j];
                    }
                    this.ecb_encrypt(st);
                    for (j = 0; j < bytes; j++) {
                        this.f[16 - bytes + j] = buff[j];
                        buff[j] ^= st[j];
                    }
                    return fell_off;

                case AES.OFB1:
                case AES.OFB2:
                case AES.OFB4:
                case AES.OFB8:
                case AES.OFB16:
                    bytes = this.mode - AES.OFB1 + 1;
                    this.ecb_encrypt(this.f);
                    for (j = 0; j < bytes; j++) {
                        buff[j] ^= this.f[j];
                    }
                    return 0;

                case AES.CTR1:
                case AES.CTR2:
                case AES.CTR4:
                case AES.CTR8:
                case AES.CTR16:
                    bytes = this.mode - AES.CTR1 + 1;
                    for (j = 0; j < 16; j++) {
                        st[j] = this.f[j];
                    }
                    this.ecb_encrypt(st);
                    for (j = 0; j < bytes; j++) {
                        buff[j] ^= st[j];
                    }
                    this.increment();
                    return 0;

                default:
                    return 0;
            }
        },

        /* Clean up and delete left-overs */
        end: function() { // clean up
            var i;

            for (i = 0; i < 4 * (this.Nr + 1); i++) {
                this.fkey[i] = this.rkey[i] = 0;
            }

            for (i = 0; i < 16; i++) {
                this.f[i] = 0;
            }
        }
    };

    /* static functions */

    AES.ROTL8 = function(x) {
        return (((x) << 8) | ((x) >>> 24));
    };

    AES.ROTL16 = function(x) {
        return (((x) << 16) | ((x) >>> 16));
    };

    AES.ROTL24 = function(x) {
        return (((x) << 24) | ((x) >>> 8));
    };

    AES.pack = function(b) { /* pack 4 bytes into a 32-bit Word */
        return (((b[3]) & 0xff) << 24) | ((b[2] & 0xff) << 16) | ((b[1] & 0xff) << 8) | (b[0] & 0xff);
    };

    AES.unpack = function(a) { /* unpack bytes from a word */
        var b = [];
        b[0] = (a & 0xff);
        b[1] = ((a >>> 8) & 0xff);
        b[2] = ((a >>> 16) & 0xff);
        b[3] = ((a >>> 24) & 0xff);
        return b;
    };

    AES.bmul = function(x, y) { /* x.y= AntiLog(Log(x) + Log(y)) */
        var ix = (x & 0xff),
            iy = (y & 0xff),
            lx = (AES.ltab[ix]) & 0xff,
            ly = (AES.ltab[iy]) & 0xff;

        if (x !== 0 && y !== 0) {
            return AES.ptab[(lx + ly) % 255];
        } else {
            return 0;
        }
    };

    //  if (x && y)

    AES.SubByte = function(a) {
        var b = AES.unpack(a);
        b[0] = AES.fbsub[b[0] & 0xff];
        b[1] = AES.fbsub[b[1] & 0xff];
        b[2] = AES.fbsub[b[2] & 0xff];
        b[3] = AES.fbsub[b[3] & 0xff];
        return AES.pack(b);
    };

    AES.product = function(x, y) { /* dot product of two 4-byte arrays */
        var xb = AES.unpack(x),
            yb = AES.unpack(y);

        return (AES.bmul(xb[0], yb[0]) ^ AES.bmul(xb[1], yb[1]) ^ AES.bmul(xb[2], yb[2]) ^ AES.bmul(xb[3], yb[3])) & 0xff;
    };

    AES.InvMixCol = function(x) { /* matrix Multiplication */
        var b = [],
            y, m;

        m = AES.pack(AES.InCo);
        b[3] = AES.product(m, x);
        m = AES.ROTL24(m);
        b[2] = AES.product(m, x);
        m = AES.ROTL24(m);
        b[1] = AES.product(m, x);
        m = AES.ROTL24(m);
        b[0] = AES.product(m, x);
        y = AES.pack(b);

        return y;
    };

    AES.InCo = [0xB, 0xD, 0x9, 0xE]; /* Inverse Coefficients */
    AES.rco = [1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47];

    AES.ptab = [
        1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53,
        95, 225, 56, 72, 216, 115, 149, 164, 247, 2, 6, 10, 30, 34, 102, 170,
        229, 52, 92, 228, 55, 89, 235, 38, 106, 190, 217, 112, 144, 171, 230, 49,
        83, 245, 4, 12, 20, 60, 68, 204, 79, 209, 104, 184, 211, 110, 178, 205,
        76, 212, 103, 169, 224, 59, 77, 215, 98, 166, 241, 8, 24, 40, 120, 136,
        131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206, 73, 219, 118, 154,
        181, 196, 87, 249, 16, 48, 80, 240, 11, 29, 39, 105, 187, 214, 97, 163,
        254, 25, 43, 125, 135, 146, 173, 236, 47, 113, 147, 174, 233, 32, 96, 160,
        251, 22, 58, 78, 210, 109, 183, 194, 93, 231, 50, 86, 250, 21, 63, 65,
        195, 94, 226, 61, 71, 201, 64, 192, 91, 237, 44, 116, 156, 191, 218, 117,
        159, 186, 213, 100, 172, 239, 42, 126, 130, 157, 188, 223, 122, 142, 137, 128,
        155, 182, 193, 88, 232, 35, 101, 175, 234, 37, 111, 177, 200, 67, 197, 84,
        252, 31, 33, 99, 165, 244, 7, 9, 27, 45, 119, 153, 176, 203, 70, 202,
        69, 207, 74, 222, 121, 139, 134, 145, 168, 227, 62, 66, 198, 81, 243, 14,
        18, 54, 90, 238, 41, 123, 141, 140, 143, 138, 133, 148, 167, 242, 13, 23,
        57, 75, 221, 124, 132, 151, 162, 253, 28, 36, 108, 180, 199, 82, 246, 1
    ];
    AES.ltab = [
        0, 255, 25, 1, 50, 2, 26, 198, 75, 199, 27, 104, 51, 238, 223, 3,
        100, 4, 224, 14, 52, 141, 129, 239, 76, 113, 8, 200, 248, 105, 28, 193,
        125, 194, 29, 181, 249, 185, 39, 106, 77, 228, 166, 114, 154, 201, 9, 120,
        101, 47, 138, 5, 33, 15, 225, 36, 18, 240, 130, 69, 53, 147, 218, 142,
        150, 143, 219, 189, 54, 208, 206, 148, 19, 92, 210, 241, 64, 70, 131, 56,
        102, 221, 253, 48, 191, 6, 139, 98, 179, 37, 226, 152, 34, 136, 145, 16,
        126, 110, 72, 195, 163, 182, 30, 66, 58, 107, 40, 84, 250, 133, 61, 186,
        43, 121, 10, 21, 155, 159, 94, 202, 78, 212, 172, 229, 243, 115, 167, 87,
        175, 88, 168, 80, 244, 234, 214, 116, 79, 174, 233, 213, 231, 230, 173, 232,
        44, 215, 117, 122, 235, 22, 11, 245, 89, 203, 95, 176, 156, 169, 81, 160,
        127, 12, 246, 111, 23, 196, 73, 236, 216, 67, 31, 45, 164, 118, 123, 183,
        204, 187, 62, 90, 251, 96, 177, 134, 59, 82, 161, 108, 170, 85, 41, 157,
        151, 178, 135, 144, 97, 190, 220, 252, 188, 149, 207, 205, 55, 63, 91, 209,
        83, 57, 132, 60, 65, 162, 109, 71, 20, 42, 158, 93, 86, 242, 211, 171,
        68, 17, 146, 217, 35, 32, 46, 137, 180, 124, 184, 38, 119, 153, 227, 165,
        103, 74, 237, 222, 197, 49, 254, 24, 13, 99, 140, 128, 192, 247, 112, 7
    ];
    AES.fbsub = [
        99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
        202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192,
        183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21,
        4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117,
        9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132,
        83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207,
        208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168,
        81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210,
        205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115,
        96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219,
        224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121,
        231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8,
        186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138,
        112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158,
        225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223,
        140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22
    ];
    AES.rbsub = [
        82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
        124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
        84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
        8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37,
        114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146,
        108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132,
        144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6,
        208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107,
        58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115,
        150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110,
        71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27,
        252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244,
        31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
        96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
        160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
        23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125
    ];
    AES.ftable = [
        0xa56363c6, 0x847c7cf8, 0x997777ee, 0x8d7b7bf6, 0xdf2f2ff, 0xbd6b6bd6,
        0xb16f6fde, 0x54c5c591, 0x50303060, 0x3010102, 0xa96767ce, 0x7d2b2b56,
        0x19fefee7, 0x62d7d7b5, 0xe6abab4d, 0x9a7676ec, 0x45caca8f, 0x9d82821f,
        0x40c9c989, 0x877d7dfa, 0x15fafaef, 0xeb5959b2, 0xc947478e, 0xbf0f0fb,
        0xecadad41, 0x67d4d4b3, 0xfda2a25f, 0xeaafaf45, 0xbf9c9c23, 0xf7a4a453,
        0x967272e4, 0x5bc0c09b, 0xc2b7b775, 0x1cfdfde1, 0xae93933d, 0x6a26264c,
        0x5a36366c, 0x413f3f7e, 0x2f7f7f5, 0x4fcccc83, 0x5c343468, 0xf4a5a551,
        0x34e5e5d1, 0x8f1f1f9, 0x937171e2, 0x73d8d8ab, 0x53313162, 0x3f15152a,
        0xc040408, 0x52c7c795, 0x65232346, 0x5ec3c39d, 0x28181830, 0xa1969637,
        0xf05050a, 0xb59a9a2f, 0x907070e, 0x36121224, 0x9b80801b, 0x3de2e2df,
        0x26ebebcd, 0x6927274e, 0xcdb2b27f, 0x9f7575ea, 0x1b090912, 0x9e83831d,
        0x742c2c58, 0x2e1a1a34, 0x2d1b1b36, 0xb26e6edc, 0xee5a5ab4, 0xfba0a05b,
        0xf65252a4, 0x4d3b3b76, 0x61d6d6b7, 0xceb3b37d, 0x7b292952, 0x3ee3e3dd,
        0x712f2f5e, 0x97848413, 0xf55353a6, 0x68d1d1b9, 0x0, 0x2cededc1,
        0x60202040, 0x1ffcfce3, 0xc8b1b179, 0xed5b5bb6, 0xbe6a6ad4, 0x46cbcb8d,
        0xd9bebe67, 0x4b393972, 0xde4a4a94, 0xd44c4c98, 0xe85858b0, 0x4acfcf85,
        0x6bd0d0bb, 0x2aefefc5, 0xe5aaaa4f, 0x16fbfbed, 0xc5434386, 0xd74d4d9a,
        0x55333366, 0x94858511, 0xcf45458a, 0x10f9f9e9, 0x6020204, 0x817f7ffe,
        0xf05050a0, 0x443c3c78, 0xba9f9f25, 0xe3a8a84b, 0xf35151a2, 0xfea3a35d,
        0xc0404080, 0x8a8f8f05, 0xad92923f, 0xbc9d9d21, 0x48383870, 0x4f5f5f1,
        0xdfbcbc63, 0xc1b6b677, 0x75dadaaf, 0x63212142, 0x30101020, 0x1affffe5,
        0xef3f3fd, 0x6dd2d2bf, 0x4ccdcd81, 0x140c0c18, 0x35131326, 0x2fececc3,
        0xe15f5fbe, 0xa2979735, 0xcc444488, 0x3917172e, 0x57c4c493, 0xf2a7a755,
        0x827e7efc, 0x473d3d7a, 0xac6464c8, 0xe75d5dba, 0x2b191932, 0x957373e6,
        0xa06060c0, 0x98818119, 0xd14f4f9e, 0x7fdcdca3, 0x66222244, 0x7e2a2a54,
        0xab90903b, 0x8388880b, 0xca46468c, 0x29eeeec7, 0xd3b8b86b, 0x3c141428,
        0x79dedea7, 0xe25e5ebc, 0x1d0b0b16, 0x76dbdbad, 0x3be0e0db, 0x56323264,
        0x4e3a3a74, 0x1e0a0a14, 0xdb494992, 0xa06060c, 0x6c242448, 0xe45c5cb8,
        0x5dc2c29f, 0x6ed3d3bd, 0xefacac43, 0xa66262c4, 0xa8919139, 0xa4959531,
        0x37e4e4d3, 0x8b7979f2, 0x32e7e7d5, 0x43c8c88b, 0x5937376e, 0xb76d6dda,
        0x8c8d8d01, 0x64d5d5b1, 0xd24e4e9c, 0xe0a9a949, 0xb46c6cd8, 0xfa5656ac,
        0x7f4f4f3, 0x25eaeacf, 0xaf6565ca, 0x8e7a7af4, 0xe9aeae47, 0x18080810,
        0xd5baba6f, 0x887878f0, 0x6f25254a, 0x722e2e5c, 0x241c1c38, 0xf1a6a657,
        0xc7b4b473, 0x51c6c697, 0x23e8e8cb, 0x7cdddda1, 0x9c7474e8, 0x211f1f3e,
        0xdd4b4b96, 0xdcbdbd61, 0x868b8b0d, 0x858a8a0f, 0x907070e0, 0x423e3e7c,
        0xc4b5b571, 0xaa6666cc, 0xd8484890, 0x5030306, 0x1f6f6f7, 0x120e0e1c,
        0xa36161c2, 0x5f35356a, 0xf95757ae, 0xd0b9b969, 0x91868617, 0x58c1c199,
        0x271d1d3a, 0xb99e9e27, 0x38e1e1d9, 0x13f8f8eb, 0xb398982b, 0x33111122,
        0xbb6969d2, 0x70d9d9a9, 0x898e8e07, 0xa7949433, 0xb69b9b2d, 0x221e1e3c,
        0x92878715, 0x20e9e9c9, 0x49cece87, 0xff5555aa, 0x78282850, 0x7adfdfa5,
        0x8f8c8c03, 0xf8a1a159, 0x80898909, 0x170d0d1a, 0xdabfbf65, 0x31e6e6d7,
        0xc6424284, 0xb86868d0, 0xc3414182, 0xb0999929, 0x772d2d5a, 0x110f0f1e,
        0xcbb0b07b, 0xfc5454a8, 0xd6bbbb6d, 0x3a16162c
    ];
    AES.rtable = [
        0x50a7f451, 0x5365417e, 0xc3a4171a, 0x965e273a, 0xcb6bab3b, 0xf1459d1f,
        0xab58faac, 0x9303e34b, 0x55fa3020, 0xf66d76ad, 0x9176cc88, 0x254c02f5,
        0xfcd7e54f, 0xd7cb2ac5, 0x80443526, 0x8fa362b5, 0x495ab1de, 0x671bba25,
        0x980eea45, 0xe1c0fe5d, 0x2752fc3, 0x12f04c81, 0xa397468d, 0xc6f9d36b,
        0xe75f8f03, 0x959c9215, 0xeb7a6dbf, 0xda595295, 0x2d83bed4, 0xd3217458,
        0x2969e049, 0x44c8c98e, 0x6a89c275, 0x78798ef4, 0x6b3e5899, 0xdd71b927,
        0xb64fe1be, 0x17ad88f0, 0x66ac20c9, 0xb43ace7d, 0x184adf63, 0x82311ae5,
        0x60335197, 0x457f5362, 0xe07764b1, 0x84ae6bbb, 0x1ca081fe, 0x942b08f9,
        0x58684870, 0x19fd458f, 0x876cde94, 0xb7f87b52, 0x23d373ab, 0xe2024b72,
        0x578f1fe3, 0x2aab5566, 0x728ebb2, 0x3c2b52f, 0x9a7bc586, 0xa50837d3,
        0xf2872830, 0xb2a5bf23, 0xba6a0302, 0x5c8216ed, 0x2b1ccf8a, 0x92b479a7,
        0xf0f207f3, 0xa1e2694e, 0xcdf4da65, 0xd5be0506, 0x1f6234d1, 0x8afea6c4,
        0x9d532e34, 0xa055f3a2, 0x32e18a05, 0x75ebf6a4, 0x39ec830b, 0xaaef6040,
        0x69f715e, 0x51106ebd, 0xf98a213e, 0x3d06dd96, 0xae053edd, 0x46bde64d,
        0xb58d5491, 0x55dc471, 0x6fd40604, 0xff155060, 0x24fb9819, 0x97e9bdd6,
        0xcc434089, 0x779ed967, 0xbd42e8b0, 0x888b8907, 0x385b19e7, 0xdbeec879,
        0x470a7ca1, 0xe90f427c, 0xc91e84f8, 0x0, 0x83868009, 0x48ed2b32,
        0xac70111e, 0x4e725a6c, 0xfbff0efd, 0x5638850f, 0x1ed5ae3d, 0x27392d36,
        0x64d90f0a, 0x21a65c68, 0xd1545b9b, 0x3a2e3624, 0xb1670a0c, 0xfe75793,
        0xd296eeb4, 0x9e919b1b, 0x4fc5c080, 0xa220dc61, 0x694b775a, 0x161a121c,
        0xaba93e2, 0xe52aa0c0, 0x43e0223c, 0x1d171b12, 0xb0d090e, 0xadc78bf2,
        0xb9a8b62d, 0xc8a91e14, 0x8519f157, 0x4c0775af, 0xbbdd99ee, 0xfd607fa3,
        0x9f2601f7, 0xbcf5725c, 0xc53b6644, 0x347efb5b, 0x7629438b, 0xdcc623cb,
        0x68fcedb6, 0x63f1e4b8, 0xcadc31d7, 0x10856342, 0x40229713, 0x2011c684,
        0x7d244a85, 0xf83dbbd2, 0x1132f9ae, 0x6da129c7, 0x4b2f9e1d, 0xf330b2dc,
        0xec52860d, 0xd0e3c177, 0x6c16b32b, 0x99b970a9, 0xfa489411, 0x2264e947,
        0xc48cfca8, 0x1a3ff0a0, 0xd82c7d56, 0xef903322, 0xc74e4987, 0xc1d138d9,
        0xfea2ca8c, 0x360bd498, 0xcf81f5a6, 0x28de7aa5, 0x268eb7da, 0xa4bfad3f,
        0xe49d3a2c, 0xd927850, 0x9bcc5f6a, 0x62467e54, 0xc2138df6, 0xe8b8d890,
        0x5ef7392e, 0xf5afc382, 0xbe805d9f, 0x7c93d069, 0xa92dd56f, 0xb31225cf,
        0x3b99acc8, 0xa77d1810, 0x6e639ce8, 0x7bbb3bdb, 0x97826cd, 0xf418596e,
        0x1b79aec, 0xa89a4f83, 0x656e95e6, 0x7ee6ffaa, 0x8cfbc21, 0xe6e815ef,
        0xd99be7ba, 0xce366f4a, 0xd4099fea, 0xd67cb029, 0xafb2a431, 0x31233f2a,
        0x3094a5c6, 0xc066a235, 0x37bc4e74, 0xa6ca82fc, 0xb0d090e0, 0x15d8a733,
        0x4a9804f1, 0xf7daec41, 0xe50cd7f, 0x2ff69117, 0x8dd64d76, 0x4db0ef43,
        0x544daacc, 0xdf0496e4, 0xe3b5d19e, 0x1b886a4c, 0xb81f2cc1, 0x7f516546,
        0x4ea5e9d, 0x5d358c01, 0x737487fa, 0x2e410bfb, 0x5a1d67b3, 0x52d2db92,
        0x335610e9, 0x1347d66d, 0x8c61d79a, 0x7a0ca137, 0x8e14f859, 0x893c13eb,
        0xee27a9ce, 0x35c961b7, 0xede51ce1, 0x3cb1477a, 0x59dfd29c, 0x3f73f255,
        0x79ce1418, 0xbf37c773, 0xeacdf753, 0x5baafd5f, 0x146f3ddf, 0x86db4478,
        0x81f3afca, 0x3ec468b9, 0x2c342438, 0x5f40a3c2, 0x72c31d16, 0xc25e2bc,
        0x8b493c28, 0x41950dff, 0x7101a839, 0xdeb30c08, 0x9ce4b4d8, 0x90c15664,
        0x6184cb7b, 0x70b632d5, 0x745c6c48, 0x4257b8d0
    ];

    return AES;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports.AES = AES;
}

},{}],"./big":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

var BIG,
    DBIG;

/* AMCL BIG number class */
BIG = function(ctx) {
    "use strict";

    /* General purpose Constructor */
    var BIG = function(x) {
        this.w = new Array(BIG.NLEN);

        switch (typeof(x)) {
            case "object":
                this.copy(x);
                break;

            case "number":
                this.zero();
                this.w[0] = x;
                break;

            default:
                this.zero();
        }
    };

    BIG.CHUNK = 32;
    BIG.MODBYTES = ctx.config["@NB"];
    BIG.BASEBITS = ctx.config["@BASE"];
    BIG.NLEN = (1 + (Math.floor((8 * BIG.MODBYTES - 1) / BIG.BASEBITS)));
    BIG.DNLEN = 2 * BIG.NLEN;
    BIG.BMASK = (1 << BIG.BASEBITS) - 1;
    BIG.BIGBITS = (8 * BIG.MODBYTES);
    BIG.NEXCESS = (1 << (BIG.CHUNK - BIG.BASEBITS - 1));
    BIG.MODINV = (Math.pow(2, -BIG.BASEBITS));

    BIG.prototype = {
        /* set to zero */
        zero: function() {
            var i;

            for (i = 0; i < BIG.NLEN; i++) {
                this.w[i] = 0;
            }

            return this;
        },

        /* set to one */
        one: function() {
            var i;

            this.w[0] = 1;
            for (i = 1; i < BIG.NLEN; i++) {
                this.w[i] = 0;
            }

            return this;
        },

        get: function(i) {
            return this.w[i];
        },

        set: function(i, x) {
            this.w[i] = x;
        },

        /* test for zero */
        iszilch: function() {
            var i;

            for (i = 0; i < BIG.NLEN; i++) {
                if (this.w[i] !== 0) {
                    return false;
                }
            }

            return true;
        },

        /* test for unity */
        isunity: function() {
            var i;

            for (i = 1; i < BIG.NLEN; i++) {
                if (this.w[i] !== 0) {
                    return false;
                }
            }

            if (this.w[0] != 1) {
                return false;
            }

            return true;
        },

        /* Conditional swap of two BIGs depending on d using XOR - no branches */
        cswap: function(b, d) {
            var c = d,
                t, i;

            c = ~(c - 1);

            for (i = 0; i < BIG.NLEN; i++) {
                t = c & (this.w[i] ^ b.w[i]);
                this.w[i] ^= t;
                b.w[i] ^= t;
            }
        },

        /* Conditional move of BIG depending on d using XOR - no branches */
        cmove: function(b, d) {
            var c = d,
                i;

            c = ~(c - 1);

            for (i = 0; i < BIG.NLEN; i++) {
                this.w[i] ^= (this.w[i] ^ b.w[i]) & c;
            }
        },

        /* copy from another BIG */
        copy: function(y) {
            var i;

            for (i = 0; i < BIG.NLEN; i++) {
                this.w[i] = y.w[i];
            }

            return this;
        },

        /* copy from bottom half of ctx.DBIG */
        hcopy: function(y) {
            var i;

            for (i = 0; i < BIG.NLEN; i++) {
                this.w[i] = y.w[i];
            }

            return this;
        },

        /* copy from ROM */
        rcopy: function(y) {
            var i;

            for (i = 0; i < BIG.NLEN; i++) {
                this.w[i] = y[i];
            }

            return this;
        },

        xortop: function(x) {
            this.w[BIG.NLEN - 1] ^= x;
        },

        ortop: function(x) {
            this.w[BIG.NLEN - 1] |= x;
        },

        /* normalise BIG - force all digits < 2^BASEBITS */
        norm: function() {
            var carry = 0,
                d, i;

            for (i = 0; i < BIG.NLEN - 1; i++) {
                d = this.w[i] + carry;
                this.w[i] = d & BIG.BMASK;
                carry = d >> BIG.BASEBITS;
            }

            this.w[BIG.NLEN - 1] = (this.w[BIG.NLEN - 1] + carry);

            return (this.w[BIG.NLEN - 1] >> ((8 * BIG.MODBYTES) % BIG.BASEBITS));
        },

        /* quick shift right by less than a word */
        fshr: function(k) {
            var r, i;

            r = this.w[0] & ((1 << k) - 1); /* shifted out part */

            for (i = 0; i < BIG.NLEN - 1; i++) {
                this.w[i] = (this.w[i] >> k) | ((this.w[i + 1] << (BIG.BASEBITS - k)) & BIG.BMASK);
            }

            this.w[BIG.NLEN - 1] = this.w[BIG.NLEN - 1] >> k;

            return r;
        },

        /* General shift right by k bits */
        shr: function(k) {
            var n = k % BIG.BASEBITS,
                m = Math.floor(k / BIG.BASEBITS),
                i;

            for (i = 0; i < BIG.NLEN - m - 1; i++) {
                this.w[i] = (this.w[m + i] >> n) | ((this.w[m + i + 1] << (BIG.BASEBITS - n)) & BIG.BMASK);
            }

            this.w[BIG.NLEN - m - 1] = this.w[BIG.NLEN - 1] >> n;

            for (i = BIG.NLEN - m; i < BIG.NLEN; i++) {
                this.w[i] = 0;
            }

            return this;
        },

        /* quick shift left by less than a word */
        fshl: function(k) {
            var i;

            this.w[BIG.NLEN - 1] = ((this.w[BIG.NLEN - 1] << k)) | (this.w[BIG.NLEN - 2] >> (BIG.BASEBITS - k));

            for (i = BIG.NLEN - 2; i > 0; i--) {
                this.w[i] = ((this.w[i] << k) & BIG.BMASK) | (this.w[i - 1] >> (BIG.BASEBITS - k));
            }

            this.w[0] = (this.w[0] << k) & BIG.BMASK;

            return (this.w[BIG.NLEN - 1] >> ((8 * BIG.MODBYTES) % BIG.BASEBITS)); /* return excess - only used in FF.java */
        },

        /* General shift left by k bits */
        shl: function(k) {
            var n = k % BIG.BASEBITS,
                m = Math.floor(k / BIG.BASEBITS),
                i;

            this.w[BIG.NLEN - 1] = (this.w[BIG.NLEN - 1 - m] << n);

            if (BIG.NLEN > m + 2) {
                this.w[BIG.NLEN - 1] |= (this.w[BIG.NLEN - m - 2] >> (BIG.BASEBITS - n));
            }

            for (i = BIG.NLEN - 2; i > m; i--) {
                this.w[i] = ((this.w[i - m] << n) & BIG.BMASK) | (this.w[i - m - 1] >> (BIG.BASEBITS - n));
            }

            this.w[m] = (this.w[0] << n) & BIG.BMASK;

            for (i = 0; i < m; i++) {
                this.w[i] = 0;
            }

            return this;
        },

        /* return length in bits */
        nbits: function() {
            var k = BIG.NLEN - 1,
                bts, c;

            this.norm();

            while (k >= 0 && this.w[k] === 0) {
                k--;
            }

            if (k < 0) {
                return 0;
            }

            bts = BIG.BASEBITS * k;
            c = this.w[k];

            while (c !== 0) {
                c = Math.floor(c / 2);
                bts++;
            }

            return bts;
        },

        /* convert this to string */
        toString: function() {
            var s = "",
                len = this.nbits(),
                b, i;

            if (len % 4 === 0) {
                len = Math.floor(len / 4);
            } else {
                len = Math.floor(len / 4);
                len++;
            }

            if (len < BIG.MODBYTES * 2) {
                len = BIG.MODBYTES * 2;
            }

            for (i = len - 1; i >= 0; i--) {
                b = new BIG(0);
                b.copy(this);
                b.shr(i * 4);
                s += (b.w[0] & 15).toString(16);
            }

            return s;
        },

        /* this+=y */
        add: function(y) {
            var i;

            for (i = 0; i < BIG.NLEN; i++) {
                this.w[i] += y.w[i];
            }

            return this;
        },

        /* return this+x */
        plus: function(x) {
            var s = new BIG(0),
                i;

            for (i = 0; i < BIG.NLEN; i++) {
                s.w[i] = this.w[i] + x.w[i];
            }

            return s;
        },

        /* this+=i, where i is int */
        inc: function(i) {
            this.norm();
            this.w[0] += i;
            return this;
        },

        /* this-=y */
        sub: function(y) {
            var i;

            for (i = 0; i < BIG.NLEN; i++) {
                this.w[i] -= y.w[i];
            }

            return this;
        },

        /* reverse subtract this=x-this */
        rsub: function(x) {
            var i;

            for (i = 0; i < BIG.NLEN; i++) {
                this.w[i] = x.w[i] - this.w[i];
            }

            return this;
        },

        /* this-=i, where i is int */
        dec: function(i) {
            this.norm();
            this.w[0] -= i;
            return this;
        },

        /* return this-x */
        minus: function(x) {
            var d = new BIG(0),
                i;

            for (i = 0; i < BIG.NLEN; i++) {
                d.w[i] = this.w[i] - x.w[i];
            }

            return d;
        },

        /* multiply by small integer */
        imul: function(c) {
            var i;

            for (i = 0; i < BIG.NLEN; i++) {
                this.w[i] *= c;
            }

            return this;
        },

        /* convert this BIG to byte array */
        tobytearray: function(b, n) {
            var c = new BIG(0),
                i;

            this.norm();
            c.copy(this);

            for (i = BIG.MODBYTES - 1; i >= 0; i--) {
                b[i + n] = c.w[0] & 0xff;
                c.fshr(8);
            }

            return this;
        },

        /* convert this to byte array */
        toBytes: function(b) {
            this.tobytearray(b, 0);
        },

        /* set this[i]+=x*y+c, and return high part */
        muladd: function(x, y, c, i) {
            var prod = x * y + c + this.w[i];
            this.w[i] = prod & BIG.BMASK;
            return ((prod - this.w[i]) * BIG.MODINV);
        },

        /* multiply by larger int */
        pmul: function(c) {
            var carry = 0,
                ak, i;

            //  this.norm();

            for (i = 0; i < BIG.NLEN; i++) {
                ak = this.w[i];
                this.w[i] = 0;
                carry = this.muladd(ak, c, carry, i);
            }

            return carry;
        },

        /* multiply by still larger int - results requires a ctx.DBIG */
        pxmul: function(c) {
            var m = new ctx.DBIG(0),
                carry = 0,
                j;

            for (j = 0; j < BIG.NLEN; j++) {
                carry = m.muladd(this.w[j], c, carry, j);
            }

            m.w[BIG.NLEN] = carry;

            return m;
        },

        /* divide by 3 */
        div3: function() {
            var carry = 0,
                ak, base, i;

            this.norm();
            base = (1 << BIG.BASEBITS);

            for (i = BIG.NLEN - 1; i >= 0; i--) {
                ak = (carry * base + this.w[i]);
                this.w[i] = Math.floor(ak / 3);
                carry = ak % 3;
            }
            return carry;
        },

        /* set x = x mod 2^m */
        mod2m: function(m) {
            var i, wd, bt, msk;

            wd = Math.floor(m / BIG.BASEBITS);
            bt = m % BIG.BASEBITS;
            msk = (1 << bt) - 1;
            this.w[wd] &= msk;

            for (i = wd + 1; i < BIG.NLEN; i++) {
                this.w[i] = 0;
            }
        },

        /* a=1/a mod 2^256. This is very fast! */
        invmod2m: function() {
            var U = new BIG(0),
                b = new BIG(0),
                c = new BIG(0),
                i, t1, t2;

            U.inc(BIG.invmod256(this.lastbits(8)));

            for (i = 8; i < BIG.BIGBITS; i <<= 1) {
                U.norm();
                b.copy(this);
                b.mod2m(i);
                t1 = BIG.smul(U, b);
                t1.shr(i);
                c.copy(this);
                c.shr(i);
                c.mod2m(i);

                t2 = BIG.smul(U, c);
                t2.mod2m(i);
                t1.add(t2);
                t1.norm();
                b = BIG.smul(t1, U);
                t1.copy(b);
                t1.mod2m(i);

                t2.one();
                t2.shl(i);
                t1.rsub(t2);
                t1.norm();
                t1.shl(i);
                U.add(t1);
            }

            U.mod2m(BIG.BIGBITS);
            this.copy(U);
            this.norm();
        },

        /* reduce this mod m */
        mod: function(m) {
            var k = 0,
                r = new BIG(0);

            this.norm();

            if (BIG.comp(this, m) < 0) {
                return;
            }

            do {
                m.fshl(1);
                k++;
            } while (BIG.comp(this, m) >= 0);

            while (k > 0) {
                m.fshr(1);

                r.copy(this);
                r.sub(m);
                r.norm();
                this.cmove(r, (1 - ((r.w[BIG.NLEN - 1] >> (BIG.CHUNK - 1)) & 1)));

                // if (BIG.comp(this,m)>=0)
                // {
                //     this.sub(m);
                //     this.norm();
                // }

                k--;
            }
        },
        /* this/=m */
        div: function(m) {
            var k = 0,
                d = 0,
                e = new BIG(1),
                b = new BIG(0),
                r = new BIG(0);

            this.norm();
            b.copy(this);
            this.zero();

            while (BIG.comp(b, m) >= 0) {
                e.fshl(1);
                m.fshl(1);
                k++;
            }

            while (k > 0) {
                m.fshr(1);
                e.fshr(1);

                r.copy(b);
                r.sub(m);
                r.norm();
                d = (1 - ((r.w[BIG.NLEN - 1] >> (BIG.CHUNK - 1)) & 1));
                b.cmove(r, d);
                r.copy(this);
                r.add(e);
                r.norm();
                this.cmove(r, d);

                // if (BIG.comp(b,m)>=0)
                // {
                //     this.add(e);
                //     this.norm();
                //     b.sub(m);
                //     b.norm();
                // }

                k--;
            }
        },
        /* return parity of this */
        parity: function() {
            return this.w[0] % 2;
        },

        /* return n-th bit of this */
        bit: function(n) {
            if ((this.w[Math.floor(n / BIG.BASEBITS)] & (1 << (n % BIG.BASEBITS))) > 0) {
                return 1;
            } else {
                return 0;
            }
        },

        /* return last n bits of this */
        lastbits: function(n) {
            var msk = (1 << n) - 1;
            this.norm();
            return (this.w[0]) & msk;
        },

        isok: function() {
            var ok = true,
                i;

            for (i = 0; i < BIG.NLEN; i++) {
                if ((this.w[i] >> BIG.BASEBITS) != 0) {
                    ok = false;
                }
            }

            return ok;
        },

        /* Jacobi Symbol (this/p). Returns 0, 1 or -1 */
        jacobi: function(p) {
            var m = 0,
                t = new BIG(0),
                x = new BIG(0),
                n = new BIG(0),
                zilch = new BIG(0),
                one = new BIG(1),
                n8, k;

            if (p.parity() === 0 || BIG.comp(this, zilch) === 0 || BIG.comp(p, one) <= 0) {
                return 0;
            }

            this.norm();
            x.copy(this);
            n.copy(p);
            x.mod(p);

            while (BIG.comp(n, one) > 0) {
                if (BIG.comp(x, zilch) === 0) {
                    return 0;
                }

                n8 = n.lastbits(3);
                k = 0;

                while (x.parity() === 0) {
                    k++;
                    x.shr(1);
                }

                if (k % 2 == 1) {
                    m += (n8 * n8 - 1) / 8;
                }

                m += (n8 - 1) * (x.lastbits(2) - 1) / 4;
                t.copy(n);
                t.mod(x);
                n.copy(x);
                x.copy(t);
                m %= 2;
            }

            if (m === 0) {
                return 1;
            } else {
                return -1;
            }
        },

        /* this=1/this mod p. Binary method */
        invmodp: function(p) {
            var u = new BIG(0),
                v = new BIG(0),
                x1 = new BIG(1),
                x2 = new BIG(0),
                t = new BIG(0),
                one = new BIG(1);

            this.mod(p);
            u.copy(this);
            v.copy(p);

            while (BIG.comp(u, one) !== 0 && BIG.comp(v, one) !== 0) {
                while (u.parity() === 0) {
                    u.shr(1);
                    if (x1.parity() !== 0) {
                        x1.add(p);
                        x1.norm();
                    }
                    x1.shr(1);
                }

                while (v.parity() === 0) {
                    v.shr(1);
                    if (x2.parity() !== 0) {
                        x2.add(p);
                        x2.norm();
                    }
                    x2.shr(1);
                }

                if (BIG.comp(u, v) >= 0) {
                    u.sub(v);
                    u.norm();
                    if (BIG.comp(x1, x2) >= 0) {
                        x1.sub(x2);
                    } else {
                        t.copy(p);
                        t.sub(x2);
                        x1.add(t);
                    }
                    x1.norm();
                } else {
                    v.sub(u);
                    v.norm();
                    if (BIG.comp(x2, x1) >= 0) {
                        x2.sub(x1);
                    } else {
                        t.copy(p);
                        t.sub(x1);
                        x2.add(t);
                    }
                    x2.norm();
                }
            }

            if (BIG.comp(u, one) === 0) {
                this.copy(x1);
            } else {
                this.copy(x2);
            }
        },

        /* return this^e mod m */
        powmod: function(e, m) {
            var a = new BIG(1),
                z = new BIG(0),
                s = new BIG(0),
                bt;

            this.norm();
            e.norm();
            z.copy(e);
            s.copy(this);

            for (;;) {
                bt = z.parity();
                z.fshr(1);
                if (bt == 1) {
                    a = BIG.modmul(a, s, m);
                }

                if (z.iszilch()) {
                    break;
                }

                s = BIG.modsqr(s, m);
            }

            return a;
        }
    };

    /* convert from byte array to BIG */
    BIG.frombytearray = function(b, n) {
        var m = new BIG(0),
            i;

        for (i = 0; i < BIG.MODBYTES; i++) {
            m.fshl(8);
            m.w[0] += b[i + n] & 0xff;
            //m.inc(b[i]&0xff);
        }

        return m;
    };

    BIG.fromBytes = function(b) {
        return BIG.frombytearray(b, 0);
    };

    /* return a*b where product fits a BIG */
    BIG.smul = function(a, b) {
        var c = new BIG(0),
            carry, i, j;

        for (i = 0; i < BIG.NLEN; i++) {
            carry = 0;

            for (j = 0; j < BIG.NLEN; j++) {
                if (i + j < BIG.NLEN) {
                    carry = c.muladd(a.w[i], b.w[j], carry, i + j);
                }
            }
        }

        return c;
    };

    /* Compare a and b, return 0 if a==b, -1 if a<b, +1 if a>b. Inputs must be normalised */
    BIG.comp = function(a, b) {
        var i;

        for (i = BIG.NLEN - 1; i >= 0; i--) {
            if (a.w[i] == b.w[i]) {
                continue;
            }

            if (a.w[i] > b.w[i]) {
                return 1;
            } else {
                return -1;
            }
        }

        return 0;
    };

    /* get 8*MODBYTES size random number */
    BIG.random = function(rng) {
        var m = new BIG(0),
            j = 0,
            r = 0,
            i, b;

        /* generate random BIG */
        for (i = 0; i < 8 * BIG.MODBYTES; i++) {
            if (j === 0) {
                r = rng.getByte();
            } else {
                r >>= 1;
            }

            b = r & 1;
            m.shl(1);
            m.w[0] += b; // m.inc(b);
            j++;
            j &= 7;
        }
        return m;
    };

    /* Create random BIG in portable way, one bit at a time */
    BIG.randomnum = function(q, rng) {
        var d = new ctx.DBIG(0),
            j = 0,
            r = 0,
            i, b, m;

        for (i = 0; i < 2 * q.nbits(); i++) {
            if (j === 0) {
                r = rng.getByte();
            } else {
                r >>= 1;
            }

            b = r & 1;
            d.shl(1);
            d.w[0] += b;
            j++;
            j &= 7;
        }

        m = d.mod(q);

        return m;
    };

    /* return NAF value as +/- 1, 3 or 5. x and x3 should be normed.
    nbs is number of bits processed, and nzs is number of trailing 0s detected */
    /*
    BIG.nafbits=function(x,x3,i)
    {
        var n=[];
        var nb=x3.bit(i)-x.bit(i);
        var j;
        n[1]=1;
        n[0]=0;
        if (nb===0) {n[0]=0; return n;}
        if (i===0) {n[0]=nb; return n;}
        if (nb>0) n[0]=1;
        else      n[0]=(-1);

        for (j=i-1;j>0;j--)
        {
            n[1]++;
            n[0]*=2;
            nb=x3.bit(j)-x.bit(j);
            if (nb>0) n[0]+=1;
            if (nb<0) n[0]-=1;
            if (n[0]>5 || n[0]<-5) break;
        }

        if (n[0]%2!==0 && j!==0)
        { // backtrack
            if (nb>0) n[0]=(n[0]-1)/2;
            if (nb<0) n[0]=(n[0]+1)/2;
            n[1]--;
        }
        while (n[0]%2===0)
        { // remove trailing zeros
            n[0]/=2;
            n[2]++;
            n[1]--;
        }
        return n;
    };
    */

    /* return a*b as ctx.DBIG */
    BIG.mul = function(a, b) {
        var c = new ctx.DBIG(0),
            d = [],
            n, s, t, i, k, co;

        //  a.norm();
        //  b.norm();

        //if (!a.isok()) alert("Problem in mul a");
        //if (!b.isok()) alert("Problem in mul b");

        for (i = 0; i < BIG.NLEN; i++) {
            d[i] = a.w[i] * b.w[i];
        }

        s = d[0];
        t = s;
        c.w[0] = t;

        for (k = 1; k < BIG.NLEN; k++) {
            s += d[k];
            t = s;
            for (i = k; i >= 1 + Math.floor(k / 2); i--) {
                t += (a.w[i] - a.w[k - i]) * (b.w[k - i] - b.w[i]);
            }
            c.w[k] = t;
        }
        for (k = BIG.NLEN; k < 2 * BIG.NLEN - 1; k++) {
            s -= d[k - BIG.NLEN];
            t = s;
            for (i = BIG.NLEN - 1; i >= 1 + Math.floor(k / 2); i--) {
                t += (a.w[i] - a.w[k - i]) * (b.w[k - i] - b.w[i]);
            }
            c.w[k] = t;
        }

        co = 0;
        for (i = 0; i < BIG.DNLEN - 1; i++) {
            n = c.w[i] + co;
            c.w[i] = n & BIG.BMASK;
            co = (n - c.w[i]) * BIG.MODINV;
        }
        c.w[BIG.DNLEN - 1] = co;

        // for (var j=0;j<BIG.NLEN;j++)
        // {
        //     t=0; for (var i=0;i<=j;i++) t+=a.w[j-i]*b.w[i];
        //     c.w[j]=t;
        // }
        // for (var j=BIG.NLEN;j<BIG.DNLEN-2;j++)
        // {
        //     t=0; for (var i=j-BIG.NLEN+1;i<BIG.NLEN;i++) t+=a.w[j-i]*b.w[i];
        //     c.w[j]=t;
        // }
        // t=a.w[BIG.NLEN-1]*b.w[BIG.NLEN-1];
        // c.w[BIG.DNLEN-2]=t;
        // var co=0;
        // for (var i=0;i<BIG.DNLEN-1;i++)
        // {
        //     n=c.w[i]+co;
        //     c.w[i]=n&BIG.BMASK;
        //     co=(n-c.w[i])*BIG.MODINV;
        // }
        // c.w[BIG.DNLEN-1]=co;

        return c;
    };

    /* return a^2 as ctx.DBIG */
    BIG.sqr = function(a) {
        var c = new ctx.DBIG(0),
            n, t, j, i, co;
        //  a.norm();

        //if (!a.isok()) alert("Problem in sqr");

        c.w[0] = a.w[0] * a.w[0];

        for (j = 1; j < BIG.NLEN - 1;) {
            t = a.w[j] * a.w[0];
            for (i = 1; i < (j + 1) >> 1; i++) {
                t += a.w[j - i] * a.w[i];
            }
            t += t;
            c.w[j] = t;
            j++;
            t = a.w[j] * a.w[0];
            for (i = 1; i < (j + 1) >> 1; i++) {
                t += a.w[j - i] * a.w[i];
            }
            t += t;
            t += a.w[j >> 1] * a.w[j >> 1];
            c.w[j] = t;
            j++;
        }

        for (j = BIG.NLEN - 1 + BIG.NLEN % 2; j < BIG.DNLEN - 3;) {
            t = a.w[BIG.NLEN - 1] * a.w[j - BIG.NLEN + 1];
            for (i = j - BIG.NLEN + 2; i < (j + 1) >> 1; i++) {
                t += a.w[j - i] * a.w[i];
            }
            t += t;
            c.w[j] = t;
            j++;
            t = a.w[BIG.NLEN - 1] * a.w[j - BIG.NLEN + 1];
            for (i = j - BIG.NLEN + 2; i < (j + 1) >> 1; i++) {
                t += a.w[j - i] * a.w[i];
            }
            t += t;
            t += a.w[j >> 1] * a.w[j >> 1];
            c.w[j] = t;
            j++;
        }

        t = a.w[BIG.NLEN - 2] * a.w[BIG.NLEN - 1];
        t += t;
        c.w[BIG.DNLEN - 3] = t;

        t = a.w[BIG.NLEN - 1] * a.w[BIG.NLEN - 1];
        c.w[BIG.DNLEN - 2] = t;

        co = 0;
        for (i = 0; i < BIG.DNLEN - 1; i++) {
            n = c.w[i] + co;
            c.w[i] = n & BIG.BMASK;
            co = (n - c.w[i]) * BIG.MODINV;
        }
        c.w[BIG.DNLEN - 1] = co;

        return c;
    };

    BIG.monty = function(m, nd, d) {
        var b = new BIG(0),
            v = [],
            dd = [],
            s, c, t, i, k;

        t = d.w[0];
        v[0] = ((t & BIG.BMASK) * nd) & BIG.BMASK;
        t += v[0] * m.w[0];
        c = d.w[1] + (t * BIG.MODINV);
        s = 0;

        for (k = 1; k < BIG.NLEN; k++) {
            t = c + s + v[0] * m.w[k];
            for (i = k - 1; i > Math.floor(k / 2); i--) {
                t += (v[k - i] - v[i]) * (m.w[i] - m.w[k - i]);
            }
            v[k] = ((t & BIG.BMASK) * nd) & BIG.BMASK;
            t += v[k] * m.w[0];
            c = (t * BIG.MODINV) + d.w[k + 1];

            dd[k] = v[k] * m.w[k];
            s += dd[k];
        }

        for (k = BIG.NLEN; k < 2 * BIG.NLEN - 1; k++) {
            t = c + s;
            for (i = BIG.NLEN - 1; i >= 1 + Math.floor(k / 2); i--) {
                t += (v[k - i] - v[i]) * (m.w[i] - m.w[k - i]);
            }
            b.w[k - BIG.NLEN] = t & BIG.BMASK;
            c = ((t - b.w[k - BIG.NLEN]) * BIG.MODINV) + d.w[k + 1];

            s -= dd[k - BIG.NLEN + 1];
        }

        b.w[BIG.NLEN - 1] = c & BIG.BMASK;

        return b;
    };

    /* return a*b mod m */
    BIG.modmul = function(a, b, m) {
        var d;

        a.mod(m);
        b.mod(m);
        d = BIG.mul(a, b);

        return d.mod(m);
    };

    /* return a^2 mod m */
    BIG.modsqr = function(a, m) {
        var d;

        a.mod(m);
        d = BIG.sqr(a);

        return d.mod(m);
    };

    /* return -a mod m */
    BIG.modneg = function(a, m) {
        a.mod(m);
        return m.minus(a);
    };

    /* Arazi and Qi inversion mod 256 */
    BIG.invmod256 = function(a) {
        var U, t1, t2, b, c;

        t1 = 0;
        c = (a >> 1) & 1;
        t1 += c;
        t1 &= 1;
        t1 = 2 - t1;
        t1 <<= 1;
        U = t1 + 1;

        // i=2
        b = a & 3;
        t1 = U * b;
        t1 >>= 2;
        c = (a >> 2) & 3;
        t2 = (U * c) & 3;
        t1 += t2;
        t1 *= U;
        t1 &= 3;
        t1 = 4 - t1;
        t1 <<= 2;
        U += t1;

        // i=4
        b = a & 15;
        t1 = U * b;
        t1 >>= 4;
        c = (a >> 4) & 15;
        t2 = (U * c) & 15;
        t1 += t2;
        t1 *= U;
        t1 &= 15;
        t1 = 16 - t1;
        t1 <<= 4;
        U += t1;

        return U;
    };
    return BIG;
};

/* AMCL double length DBIG number class */
DBIG = function(ctx) {
    "use strict";

    /* constructor */
    var DBIG = function(x) {
        this.w = [];
        this.zero();
        this.w[0] = x;
    };

    DBIG.prototype = {

        /* set this=0 */
        zero: function() {
            for (var i = 0; i < ctx.BIG.DNLEN; i++) {
                this.w[i] = 0;
            }
            return this;
        },

        /* set this=b */
        copy: function(b) {
            for (var i = 0; i < ctx.BIG.DNLEN; i++) {
                this.w[i] = b.w[i];
            }
            return this;
        },


        /* copy from ctx.BIG */
        hcopy: function(b) {
            var i;

            for (i = 0; i < ctx.BIG.NLEN; i++) {
                this.w[i] = b.w[i];
            }

            for (i = ctx.BIG.NLEN; i < ctx.BIG.DNLEN; i++) {
                this.w[i] = 0;
            }

            return this;
        },

        ucopy: function(b) {
            var i;

            for (i = 0; i < ctx.BIG.NLEN; i++) {
                this.w[i] = 0;
            }

            for (i = ctx.BIG.NLEN; i < ctx.BIG.DNLEN; i++) {
                this.w[i] = b.w[i - ctx.BIG.NLEN];
            }

            return this;
        },

        /* normalise this */
        norm: function() {
            var carry = 0,
                d, i;

            for (i = 0; i < ctx.BIG.DNLEN - 1; i++) {
                d = this.w[i] + carry;
                this.w[i] = d & ctx.BIG.BMASK;
                carry = d >> ctx.BIG.BASEBITS;
            }
            this.w[ctx.BIG.DNLEN - 1] = (this.w[ctx.BIG.DNLEN - 1] + carry);

            return this;
        },

        /* set this[i]+=x*y+c, and return high part */
        muladd: function(x, y, c, i) {
            var prod = x * y + c + this.w[i];
            this.w[i] = prod & ctx.BIG.BMASK;
            return ((prod - this.w[i]) * ctx.BIG.MODINV);
        },

        /* shift this right by k bits */
        shr: function(k) {
            var n = k % ctx.BIG.BASEBITS,
                m = Math.floor(k / ctx.BIG.BASEBITS),
                i;

            for (i = 0; i < ctx.BIG.DNLEN - m - 1; i++) {
                this.w[i] = (this.w[m + i] >> n) | ((this.w[m + i + 1] << (ctx.BIG.BASEBITS - n)) & ctx.BIG.BMASK);
            }

            this.w[ctx.BIG.DNLEN - m - 1] = this.w[ctx.BIG.DNLEN - 1] >> n;

            for (i = ctx.BIG.DNLEN - m; i < ctx.BIG.DNLEN; i++) {
                this.w[i] = 0;
            }

            return this;
        },

        /* shift this left by k bits */
        shl: function(k) {
            var n = k % ctx.BIG.BASEBITS,
                m = Math.floor(k / ctx.BIG.BASEBITS),
                i;

            this.w[ctx.BIG.DNLEN - 1] = ((this.w[ctx.BIG.DNLEN - 1 - m] << n)) | (this.w[ctx.BIG.DNLEN - m - 2] >> (ctx.BIG.BASEBITS - n));

            for (i = ctx.BIG.DNLEN - 2; i > m; i--) {
                this.w[i] = ((this.w[i - m] << n) & ctx.BIG.BMASK) | (this.w[i - m - 1] >> (ctx.BIG.BASEBITS - n));
            }

            this.w[m] = (this.w[0] << n) & ctx.BIG.BMASK;

            for (i = 0; i < m; i++) {
                this.w[i] = 0;
            }

            return this;
        },

        /* Conditional move of ctx.BIG depending on d using XOR - no branches */
        cmove: function(b, d) {
            var c = d,
                i;

            c = ~(c - 1);

            for (i = 0; i < ctx.BIG.DNLEN; i++) {
                this.w[i] ^= (this.w[i] ^ b.w[i]) & c;
            }
        },

        /* this+=x */
        add: function(x) {
            for (var i = 0; i < ctx.BIG.DNLEN; i++) {
                this.w[i] += x.w[i];
            }
        },

        /* this-=x */
        sub: function(x) {
            for (var i = 0; i < ctx.BIG.DNLEN; i++) {
                this.w[i] -= x.w[i];
            }
        },

        rsub: function(x) {
            for (var i = 0; i < ctx.BIG.DNLEN; i++) {
                this.w[i] = x.w[i] - this.w[i];
            }
        },

        /* return number of bits in this */
        nbits: function() {
            var k = ctx.BIG.DNLEN - 1,
                bts, c;

            this.norm();

            while (k >= 0 && this.w[k] === 0) {
                k--;
            }

            if (k < 0) {
                return 0;
            }

            bts = ctx.BIG.BASEBITS * k;
            c = this.w[k];

            while (c !== 0) {
                c = Math.floor(c / 2);
                bts++;
            }

            return bts;
        },

        /* convert this to string */
        toString: function() {
            var s = "",
                len = this.nbits(),
                b, i;

            if (len % 4 === 0) {
                len = Math.floor(len / 4);
            } else {
                len = Math.floor(len / 4);
                len++;
            }

            for (i = len - 1; i >= 0; i--) {
                b = new DBIG(0);
                b.copy(this);
                b.shr(i * 4);
                s += (b.w[0] & 15).toString(16);
            }

            return s;
        },

        /* reduces this DBIG mod a ctx.BIG, and returns the ctx.BIG */
        mod: function(c) {
            var k = 0,
                m = new DBIG(0),
                dr = new DBIG(0),
                r = new ctx.BIG(0);

            this.norm();
            m.hcopy(c);
            r.hcopy(this);

            if (DBIG.comp(this, m) < 0) {
                return r;
            }

            do {
                m.shl(1);
                k++;
            } while (DBIG.comp(this, m) >= 0);

            while (k > 0) {
                m.shr(1);

                dr.copy(this);
                dr.sub(m);
                dr.norm();
                this.cmove(dr, (1 - ((dr.w[ctx.BIG.DNLEN - 1] >> (ctx.BIG.CHUNK - 1)) & 1)));

                // if (DBIG.comp(this,m)>=0)
                // {
                //     this.sub(m);
                //     this.norm();
                // }

                k--;
            }

            r.hcopy(this);

            return r;
        },

        /* this/=c */
        div: function(c) {
            var d = 0,
                k = 0,
                m = new DBIG(0),
                dr = new DBIG(0),
                r = new ctx.BIG(0),
                a = new ctx.BIG(0),
                e = new ctx.BIG(1);

            m.hcopy(c);
            this.norm();

            while (DBIG.comp(this, m) >= 0) {
                e.fshl(1);
                m.shl(1);
                k++;
            }

            while (k > 0) {
                m.shr(1);
                e.shr(1);

                dr.copy(this);
                dr.sub(m);
                dr.norm();
                d = (1 - ((dr.w[ctx.BIG.DNLEN - 1] >> (ctx.BIG.CHUNK - 1)) & 1));
                this.cmove(dr, d);
                r.copy(a);
                r.add(e);
                r.norm();
                a.cmove(r, d);

                // if (DBIG.comp(this,m)>0)
                // {
                //     a.add(e);
                //     a.norm();
                //     this.sub(m);
                //     this.norm();
                // }

                k--;
            }
            return a;
        },

        /* split this DBIG at position n, return higher half, keep lower half */
        split: function(n) {
            var t = new ctx.BIG(0),
                m = n % ctx.BIG.BASEBITS,
                carry = this.w[ctx.BIG.DNLEN - 1] << (ctx.BIG.BASEBITS - m),
                nw, i;

            for (i = ctx.BIG.DNLEN - 2; i >= ctx.BIG.NLEN - 1; i--) {
                nw = (this.w[i] >> m) | carry;
                carry = (this.w[i] << (ctx.BIG.BASEBITS - m)) & ctx.BIG.BMASK;
                t.w[i - ctx.BIG.NLEN + 1] = nw;
            }

            this.w[ctx.BIG.NLEN - 1] &= ((1 << m) - 1);

            return t;
        }

    };

    /* Compare a and b, return 0 if a==b, -1 if a<b, +1 if a>b. Inputs must be normalised */
    DBIG.comp = function(a, b) {
        var i;

        for (i = ctx.BIG.DNLEN - 1; i >= 0; i--) {
            if (a.w[i] == b.w[i]) {
                continue;
            }

            if (a.w[i] > b.w[i]) {
                return 1;
            } else {
                return -1;
            }
        }

        return 0;
    };

    return DBIG;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = {
        BIG: BIG,
        DBIG: DBIG
    };
}

},{}],"./ecdh":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

var ECDH = function(ctx) {
    "use strict";

    var ECDH = {

        INVALID_PUBLIC_KEY: -2,
        ERROR: -3,
        INVALID: -4,
        EFS: ctx.BIG.MODBYTES,
        EGS: ctx.BIG.MODBYTES,
        EAS: 16,
        EBS: 16,
        SHA256: 32,
        SHA384: 48,
        SHA512: 64,

        HASH_TYPE: 64,

        /* Convert Integer to n-byte array */
        inttobytes: function(n, len) {
            var b = [],
                i;

            for (i = 0; i < len; i++) {
                b[i] = 0;
            }

            i = len;
            while (n > 0 && i > 0) {
                i--;
                b[i] = (n & 0xff);
                n = Math.floor(n / 256);
            }

            return b;
        },

        bytestostring: function(b) {
            var s = "",
                len = b.length,
                ch, i;

            for (i = 0; i < len; i++) {
                ch = b[i];
                s += ((ch >>> 4) & 15).toString(16);
                s += (ch & 15).toString(16);

            }

            return s;
        },

        stringtobytes: function(s) {
            var b = [],
                i;

            for (i = 0; i < s.length; i++) {
                b.push(s.charCodeAt(i));
            }

            return b;
        },

        hashit: function(sha, A, n, B, pad) {
            var R = [],
                H, W, i, len;

            if (sha == this.SHA256) {
                H = new ctx.HASH256();
                H.process_array(A);

                if (n > 0) {
                    H.process_num(n);
                }

                if (B != null) {
                    H.process_array(B);
                }

                R = H.hash();
            } else if (sha == this.SHA384) {
                H = new ctx.HASH384();
                H.process_array(A);

                if (n > 0) {
                    H.process_num(n);
                }

                if (B != null) {
                    H.process_array(B);
                }

                R = H.hash();
            } else if (sha == this.SHA512) {
                H = new ctx.HASH512();
                H.process_array(A);

                if (n > 0) {
                    H.process_num(n);
                }

                if (B != null) {
                    H.process_array(B);
                }

                R = H.hash();
            }

            if (R.length == 0) {
                return null;
            }

            if (pad == 0) {
                return R;
            }

            W = [];

            len = ctx.BIG.MODBYTES;

            if (sha >= len) {
                for (i = 0; i < len; i++) {
                    W[i] = R[i];
                }
            } else {
                for (i = 0; i < sha; i++) {
                    W[i + len - sha] = R[i];
                }

                for (i = 0; i < len - sha; i++) {
                    W[i] = 0;
                }
            }

            return W;
        },

        KDF1: function(sha, Z, olen) {
            /* NOTE: the parameter olen is the length of the output K in bytes */
            var hlen = sha,
                K = [],
                B = [],
                k = 0,
                counter, cthreshold, i;

            for (i = 0; i < K.length; i++) {
                K[i] = 0; // redundant?
            }

            cthreshold = Math.floor(olen / hlen);
            if (olen % hlen !== 0) {
                cthreshold++;
            }

            for (counter = 0; counter < cthreshold; counter++) {
                B = this.hashit(sha, Z, counter, null, 0);

                if (k + hlen > olen) {
                    for (i = 0; i < olen % hlen; i++) {
                        K[k++] = B[i];
                    }
                } else {
                    for (i = 0; i < hlen; i++) {
                        K[k++] = B[i];
                    }
                }
            }

            return K;
        },

        KDF2: function(sha, Z, P, olen) {
            /* NOTE: the parameter olen is the length of the output k in bytes */
            var hlen = sha,
                K = [],
                B = [],
                k = 0,
                counter, cthreshold, i;

            for (i = 0; i < K.length; i++) {
                K[i] = 0; // redundant?
            }

            cthreshold = Math.floor(olen / hlen);
            if (olen % hlen !== 0) {
                cthreshold++;
            }

            for (counter = 1; counter <= cthreshold; counter++) {
                B = this.hashit(sha, Z, counter, P, 0);

                if (k + hlen > olen) {
                    for (i = 0; i < olen % hlen; i++) {
                        K[k++] = B[i];
                    }
                } else {
                    for (i = 0; i < hlen; i++) {
                        K[k++] = B[i];
                    }
                }
            }

            return K;
        },

        /* Password based Key Derivation Function */
        /* Input password p, salt s, and repeat count */
        /* Output key of length olen */

        PBKDF2: function(sha, Pass, Salt, rep, olen) {
            var F = new Array(sha),
                U = [],
                S = [],
                K = [],
                opt = 0,
                i, j, k, d, N, key;

            d = Math.floor(olen / sha);

            if (olen % sha !== 0) {
                d++;
            }

            opt = 0;

            for (i = 1; i <= d; i++) {
                for (j = 0; j < Salt.length; j++) {
                    S[j] = Salt[j];
                }

                N = this.inttobytes(i, 4);

                for (j = 0; j < 4; j++) {
                    S[Salt.length + j] = N[j];
                }

                this.HMAC(sha, S, Pass, F);

                for (j = 0; j < sha; j++) {
                    U[j] = F[j];
                }

                for (j = 2; j <= rep; j++) {
                    this.HMAC(sha, U, Pass, U);
                    for (k = 0; k < sha; k++) {
                        F[k] ^= U[k];
                    }
                }

                for (j = 0; j < sha; j++) {
                    K[opt++] = F[j];
                }
            }

            key = [];
            for (i = 0; i < olen; i++) {
                key[i] = K[i];
            }

            return key;
        },

        HMAC: function(sha, M, K, tag) {
            /* Input is from an octet m        *
             * olen is requested output length in bytes. k is the key  *
             * The output is the calculated tag */
            var olen = tag.length,
                B = [],
                b = 64,
                K0, i;

            if (sha > 32) {
                b = 128;
            }

            K0 = new Array(b);

            //b=K0.length;
            if (olen < 4) {
                return 0;
            }

            for (i = 0; i < b; i++) {
                K0[i] = 0;
            }

            if (K.length > b) {
                B = this.hashit(sha, K, 0, null, 0);
                for (i = 0; i < sha; i++) {
                    K0[i] = B[i];
                }
            } else {
                for (i = 0; i < K.length; i++) {
                    K0[i] = K[i];
                }
            }

            for (i = 0; i < b; i++) {
                K0[i] ^= 0x36;
            }

            B = this.hashit(sha, K0, 0, M, 0);

            for (i = 0; i < b; i++) {
                K0[i] ^= 0x6a;
            }

            B = this.hashit(sha, K0, 0, B, olen);

            for (i = 0; i < olen; i++) {
                tag[i] = B[i];
            }

            return 1;
        },

        /* ctx.AES encryption/decryption */

        AES_CBC_IV0_ENCRYPT: function(K, M) { /* ctx.AES CBC encryption, with Null IV and key K */
            /* Input is from an octet string M, output is to an octet string C */
            /* Input is padded as necessary to make up a full final block */
            var a = new ctx.AES(),
                buff = [],
                C = [],
                fin, padlen, i, j, ipt, opt;
            /*var clen=16+(Math.floor(M.length/16))*16;*/

            a.init(ctx.AES.CBC, K.length, K, null);

            ipt = opt = 0;
            fin = false;

            for (;;) {
                for (i = 0; i < 16; i++) {
                    if (ipt < M.length) {
                        buff[i] = M[ipt++];
                    } else {
                        fin = true;
                        break;
                    }
                }

                if (fin) {
                    break;
                }

                a.encrypt(buff);

                for (i = 0; i < 16; i++) {
                    C[opt++] = buff[i];
                }
            }

            /* last block, filled up to i-th index */

            padlen = 16 - i;
            for (j = i; j < 16; j++) {
                buff[j] = padlen;
            }
            a.encrypt(buff);
            for (i = 0; i < 16; i++) {
                C[opt++] = buff[i];
            }
            a.end();

            return C;
        },

        AES_CBC_IV0_DECRYPT: function(K, C) { /* padding is removed */
            var a = new ctx.AES(),
                buff = [],
                MM = [],
                ipt = 0,
                opt = 0,
                M, ch, fin, bad, padlen, i;

            a.init(ctx.AES.CBC, K.length, K, null);

            if (C.length === 0) {
                return [];
            }
            ch = C[ipt++];

            fin = false;

            for (;;) {
                for (i = 0; i < 16; i++) {
                    buff[i] = ch;
                    if (ipt >= C.length) {
                        fin = true;
                        break;
                    } else {
                        ch = C[ipt++];
                    }
                }
                a.decrypt(buff);
                if (fin) {
                    break;
                }

                for (i = 0; i < 16; i++) {
                    MM[opt++] = buff[i];
                }
            }

            a.end();
            bad = false;
            padlen = buff[15];

            if (i != 15 || padlen < 1 || padlen > 16) {
                bad = true;
            }

            if (padlen >= 2 && padlen <= 16) {
                for (i = 16 - padlen; i < 16; i++) {
                    if (buff[i] != padlen) {
                        bad = true;
                    }
                }
            }

            if (!bad) {
                for (i = 0; i < 16 - padlen; i++) {
                    MM[opt++] = buff[i];
                }
            }

            M = [];
            if (bad) {
                return M;
            }

            for (i = 0; i < opt; i++) {
                M[i] = MM[i];
            }

            return M;
        },

        KEY_PAIR_GENERATE: function(RNG, S, W) {
            var res = 0,
                r, gx, gy, s,
                G, WP;
            //      var T=[];
            G = new ctx.ECP(0);

            gx = new ctx.BIG(0);
            gx.rcopy(ctx.ROM_CURVE.CURVE_Gx);

            if (ctx.ECP.CURVETYPE != ctx.ECP.MONTGOMERY) {
                gy = new ctx.BIG(0);
                gy.rcopy(ctx.ROM_CURVE.CURVE_Gy);
                G.setxy(gx, gy);
            } else {
                G.setx(gx);
            }

            r = new ctx.BIG(0);
            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            if (RNG === null) {
                s = ctx.BIG.fromBytes(S);
                s.mod(r);
            } else {
                s = ctx.BIG.randomnum(r, RNG);
                // s.toBytes(T);
                // for (var i=0;i<this.EGS;i++) S[i]=T[i];
            }

            //if (ROM.AES_S>0)
            //{
            //  s.mod2m(2*ROM.AES_S);
            //}

            s.toBytes(S);

            WP = G.mul(s);
            WP.toBytes(W);

            return res;
        },

        PUBLIC_KEY_VALIDATE: function(W) {
            var WP = ctx.ECP.fromBytes(W),
                res = 0,
                r, q, nb, k;

            r = new ctx.BIG(0);
            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            if (WP.is_infinity()) {
                res = this.INVALID_PUBLIC_KEY;
            }

            if (res === 0) {
                q = new ctx.BIG(0);
                q.rcopy(ctx.ROM_FIELD.Modulus);
                nb = q.nbits();
                k = new ctx.BIG(1);
                k.shl(Math.floor((nb + 4) / 2));
                k.add(q);
                k.div(r);

                while (k.parity() == 0) {
                    k.shr(1);
                    WP.dbl();
                }

                if (!k.isunity()) {
                    WP = WP.mul(k);
                }

                if (WP.is_infinity()) {
                    res = this.INVALID_PUBLIC_KEY;
                }
            }

            return res;
        },

        ECPSVDP_DH: function(S, WD, Z) {
            var T = [],
                res = 0,
                r, s, i,
                W;

            s = ctx.BIG.fromBytes(S);

            W = ctx.ECP.fromBytes(WD);
            if (W.is_infinity()) {
                res = this.ERROR;
            }

            if (res === 0) {
                r = new ctx.BIG(0);
                r.rcopy(ctx.ROM_CURVE.CURVE_Order);
                s.mod(r);
                W = W.mul(s);

                if (W.is_infinity()) {
                    res = this.ERROR;
                } else {
                    W.getX().toBytes(T);
                    for (i = 0; i < this.EFS; i++) {
                        Z[i] = T[i];
                    }
                }
            }

            return res;
        },

        ECPSP_DSA: function(sha, RNG, S, F, C, D) {
            var T = [],
                i, gx, gy, r, s, f, c, d, u, vx, w,
                G, V, B;

            B = this.hashit(sha, F, 0, null, ctx.BIG.MODBYTES);

            gx = new ctx.BIG(0);
            gx.rcopy(ctx.ROM_CURVE.CURVE_Gx);
            gy = new ctx.BIG(0);
            gy.rcopy(ctx.ROM_CURVE.CURVE_Gy);

            G = new ctx.ECP(0);
            G.setxy(gx, gy);
            r = new ctx.BIG(0);
            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            s = ctx.BIG.fromBytes(S);
            f = ctx.BIG.fromBytes(B);

            c = new ctx.BIG(0);
            d = new ctx.BIG(0);
            V = new ctx.ECP();

            do {
                u = ctx.BIG.randomnum(r, RNG);
                w = ctx.BIG.randomnum(r, RNG);
                //if (ROM.AES_S>0)
                //{
                //  u.mod2m(2*ROM.AES_S);
                //}
                V.copy(G);
                V = V.mul(u);
                vx = V.getX();
                c.copy(vx);
                c.mod(r);
                if (c.iszilch()) {
                    continue;
                }
                u = ctx.BIG.modmul(u, w, r);
                u.invmodp(r);
                d = ctx.BIG.modmul(s, c, r);
                d.add(f);
                d = ctx.BIG.modmul(d, w, r);
                d = ctx.BIG.modmul(u, d, r);
            } while (d.iszilch());

            c.toBytes(T);
            for (i = 0; i < this.EFS; i++) {
                C[i] = T[i];
            }
            d.toBytes(T);
            for (i = 0; i < this.EFS; i++) {
                D[i] = T[i];
            }

            return 0;
        },

        ECPVP_DSA: function(sha, W, F, C, D) {
            var B = [],
                res = 0,
                r, gx, gy, f, c, d, h2,
                G, WP, P;

            B = this.hashit(sha, F, 0, null, ctx.BIG.MODBYTES);

            gx = new ctx.BIG(0);
            gx.rcopy(ctx.ROM_CURVE.CURVE_Gx);
            gy = new ctx.BIG(0);
            gy.rcopy(ctx.ROM_CURVE.CURVE_Gy);

            G = new ctx.ECP(0);
            G.setxy(gx, gy);
            r = new ctx.BIG(0);
            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            c = ctx.BIG.fromBytes(C);
            d = ctx.BIG.fromBytes(D);
            f = ctx.BIG.fromBytes(B);

            if (c.iszilch() || ctx.BIG.comp(c, r) >= 0 || d.iszilch() || ctx.BIG.comp(d, r) >= 0) {
                res = this.INVALID;
            }

            if (res === 0) {
                d.invmodp(r);
                f = ctx.BIG.modmul(f, d, r);
                h2 = ctx.BIG.modmul(c, d, r);

                WP = ctx.ECP.fromBytes(W);
                if (WP.is_infinity()) {
                    res = this.ERROR;
                } else {
                    P = new ctx.ECP();
                    P.copy(WP);
                    P = P.mul2(h2, G, f);

                    if (P.is_infinity()) {
                        res = this.INVALID;
                    } else {
                        d = P.getX();
                        d.mod(r);
                        if (ctx.BIG.comp(d, c) !== 0) {
                            res = this.INVALID;
                        }
                    }
                }
            }

            return res;
        },

        ECIES_ENCRYPT: function(sha, P1, P2, RNG, W, M, V, T) {
            var Z = [],
                VZ = [],
                K1 = [],
                K2 = [],
                U = [],
                C = [],
                K, L2, AC, i;

            if (this.KEY_PAIR_GENERATE(RNG, U, V) !== 0) {
                return C;
            }

            if (this.ECPSVDP_DH(U, W, Z) !== 0) {
                return C;
            }

            for (i = 0; i < 2 * this.EFS + 1; i++) {
                VZ[i] = V[i];
            }

            for (i = 0; i < this.EFS; i++) {
                VZ[2 * this.EFS + 1 + i] = Z[i];
            }

            K = this.KDF2(sha, VZ, P1, this.EFS);

            for (i = 0; i < this.EAS; i++) {
                K1[i] = K[i];
                K2[i] = K[this.EAS + i];
            }

            C = this.AES_CBC_IV0_ENCRYPT(K1, M);

            L2 = this.inttobytes(P2.length, 8);

            AC = [];
            for (i = 0; i < C.length; i++) {
                AC[i] = C[i];
            }
            for (i = 0; i < P2.length; i++) {
                AC[C.length + i] = P2[i];
            }
            for (i = 0; i < 8; i++) {
                AC[C.length + P2.length + i] = L2[i];
            }

            this.HMAC(sha, AC, K2, T);

            return C;
        },

        ECIES_DECRYPT: function(sha, P1, P2, V, C, T, U) {
            var Z = [],
                VZ = [],
                K1 = [],
                K2 = [],
                TAG = new Array(T.length),
                M = [],
                K, L2, AC, same, i;

            if (this.ECPSVDP_DH(U, V, Z) !== 0) {
                return M;
            }

            for (i = 0; i < 2 * this.EFS + 1; i++) {
                VZ[i] = V[i];
            }

            for (i = 0; i < this.EFS; i++) {
                VZ[2 * this.EFS + 1 + i] = Z[i];
            }

            K = this.KDF2(sha, VZ, P1, this.EFS);

            for (i = 0; i < this.EAS; i++) {
                K1[i] = K[i];
                K2[i] = K[this.EAS + i];
            }

            M = this.AES_CBC_IV0_DECRYPT(K1, C);

            if (M.length === 0) {
                return M;
            }

            L2 = this.inttobytes(P2.length, 8);

            AC = [];

            for (i = 0; i < C.length; i++) {
                AC[i] = C[i];
            }
            for (i = 0; i < P2.length; i++) {
                AC[C.length + i] = P2[i];
            }
            for (i = 0; i < 8; i++) {
                AC[C.length + P2.length + i] = L2[i];
            }

            this.HMAC(sha, AC, K2, TAG);

            same = true;
            for (i = 0; i < T.length; i++) {
                if (T[i] != TAG[i]) {
                    same = false;
                }
            }

            if (!same) {
                return [];
            }

            return M;
        }
    };

    return ECDH;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports.ECDH = ECDH;
}

},{}],"./ecp2":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* AMCL Weierstrass elliptic curve functions over ctx.FP2 */

var ECP2 = function(ctx) {
    "use strict";

    /* Constructor, set this=O */
    var ECP2 = function() {
        this.x = new ctx.FP2(0);
        this.y = new ctx.FP2(1);
        this.z = new ctx.FP2(0);
        this.INF = true;
    };

    ECP2.prototype = {
        /* Test this=O? */
        is_infinity: function() {
            if (this.INF) {
                return true;
            }

            this.x.reduce();
            this.y.reduce();
            this.z.reduce();
            this.INF = (this.x.iszilch() && this.z.iszilch());

            return this.INF;
        },

        /* copy this=P */
        copy: function(P) {
            this.x.copy(P.x);
            this.y.copy(P.y);
            this.z.copy(P.z);
            this.INF = P.INF;
        },

        /* set this=O */
        inf: function() {
            this.INF = true;
            this.x.zero();
            this.y.one();
            this.z.zero();
        },

        /* conditional move of Q to P dependant on d */
        cmove: function(Q, d) {
            var bd;

            this.x.cmove(Q.x, d);
            this.y.cmove(Q.y, d);
            this.z.cmove(Q.z, d);

            bd = (d !== 0) ? true : false;
            this.INF ^= (this.INF ^ Q.INF) & bd;
        },

        /* Constant time select from pre-computed table */
        select: function(W, b) {
            var MP = new ECP2(),
                m = b >> 31,
                babs = (b ^ m) - m;

            babs = (babs - 1) / 2;

            this.cmove(W[0], ECP2.teq(babs, 0)); // conditional move
            this.cmove(W[1], ECP2.teq(babs, 1));
            this.cmove(W[2], ECP2.teq(babs, 2));
            this.cmove(W[3], ECP2.teq(babs, 3));
            this.cmove(W[4], ECP2.teq(babs, 4));
            this.cmove(W[5], ECP2.teq(babs, 5));
            this.cmove(W[6], ECP2.teq(babs, 6));
            this.cmove(W[7], ECP2.teq(babs, 7));

            MP.copy(this);
            MP.neg();
            this.cmove(MP, (m & 1));
        },

        /* Test P == Q */
        equals: function(Q) {
            var a, b;

            if (this.is_infinity() && Q.is_infinity()) {
                return true;
            }

            if (this.is_infinity() || Q.is_infinity()) {
                return false;
            }

            a = new ctx.FP2(0);
            a.copy(this.x);
            b = new ctx.FP2(0);
            b.copy(Q.x);

            a.copy(this.x);
            a.mul(Q.z);
            a.reduce();
            b.copy(Q.x);
            b.mul(this.z);
            b.reduce();
            if (!a.equals(b)) {
                return false;
            }

            a.copy(this.y);
            a.mul(Q.z);
            a.reduce();
            b.copy(Q.y);
            b.mul(this.z);
            b.reduce();
            if (!a.equals(b)) {
                return false;
            }

            return true;
        },

        /* set this=-this */
        neg: function() {
            //      if (this.is_infinity()) return;
            this.y.norm();
            this.y.neg();
            this.y.norm();
            return;
        },

        /* convert this to affine, from (x,y,z) to (x,y) */
        affine: function() {
            var one;

            if (this.is_infinity()) {
                return;
            }

            one = new ctx.FP2(1);

            if (this.z.equals(one)) {
                this.x.reduce();
                this.y.reduce();
                return;
            }

            this.z.inverse();

            this.x.mul(this.z);
            this.x.reduce();
            this.y.mul(this.z);
            this.y.reduce();
            this.z.copy(one);
        },

        /* extract affine x as ctx.FP2 */
        getX: function() {
            this.affine();
            return this.x;
        },

        /* extract affine y as ctx.FP2 */
        getY: function() {
            this.affine();
            return this.y;
        },

        /* extract projective x */
        getx: function() {
            return this.x;
        },

        /* extract projective y */
        gety: function() {
            return this.y;
        },

        /* extract projective z */
        getz: function() {
            return this.z;
        },

        /* convert this to byte array */
        toBytes: function(b) {
            var t = [],
                i;

            this.affine();
            this.x.getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i] = t[i];
            }
            this.x.getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + ctx.BIG.MODBYTES] = t[i];
            }

            this.y.getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 2 * ctx.BIG.MODBYTES] = t[i];
            }
            this.y.getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 3 * ctx.BIG.MODBYTES] = t[i];
            }
        },

        /* convert this to hex string */
        toString: function() {
            if (this.is_infinity()) {
                return "infinity";
            }
            this.affine();
            return "(" + this.x.toString() + "," + this.y.toString() + ")";
        },

        /* set this=(x,y) */
        setxy: function(ix, iy) {
            var rhs, y2;

            this.x.copy(ix);
            this.y.copy(iy);
            this.z.one();

            rhs = ECP2.RHS(this.x);

            y2 = new ctx.FP2(this.y); //y2.copy(this.y);
            y2.sqr();

            if (y2.equals(rhs)) {
                this.INF = false;
            } else {
                this.inf();
            }
        },

        /* set this=(x,.) */
        setx: function(ix) {
            var rhs;

            this.x.copy(ix);
            this.z.one();

            rhs = ECP2.RHS(this.x);

            if (rhs.sqrt()) {
                this.y.copy(rhs);
                this.INF = false;
            } else {
                this.inf();
            }
        },

        /* set this*=q, where q is Modulus, using Frobenius */
        frob: function(X) {
            var X2;

            if (this.INF) {
                return;
            }

            X2 = new ctx.FP2(X); //X2.copy(X);
            X2.sqr();
            this.x.conj();
            this.y.conj();
            this.z.conj();
            this.z.reduce();
            this.x.mul(X2);
            this.y.mul(X2);
            this.y.mul(X);
        },

        /* this+=this */
        dbl: function() {
            var iy, t0, t1, t2, x3, y3;

            if (this.INF) {
                return -1;
            }

            iy = new ctx.FP2(0);
            iy.copy(this.y); //FP2 iy=new FP2(y);
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                iy.mul_ip();
                iy.norm();
            }

            t0 = new ctx.FP2(0);
            t0.copy(this.y); //FP2 t0=new FP2(y);                  //***** Change
            t0.sqr();
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                t0.mul_ip();
            }
            t1 = new ctx.FP2(0);
            t1.copy(iy); //FP2 t1=new FP2(iy);
            t1.mul(this.z);
            t2 = new ctx.FP2(0);
            t2.copy(this.z); //FP2 t2=new FP2(z);
            t2.sqr();

            this.z.copy(t0);
            this.z.add(t0);
            this.z.norm();
            this.z.add(this.z);
            this.z.add(this.z);
            this.z.norm();

            t2.imul(3 * ctx.ROM_CURVE.CURVE_B_I);
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                t2.mul_ip();
                t2.norm();
            }

            x3 = new ctx.FP2(0);
            x3.copy(t2); //FP2 x3=new FP2(t2);
            x3.mul(this.z);

            y3 = new ctx.FP2(0);
            y3.copy(t0); //FP2 y3=new FP2(t0);

            y3.add(t2);
            y3.norm();
            this.z.mul(t1);
            t1.copy(t2);
            t1.add(t2);
            t2.add(t1);
            t2.norm();
            t0.sub(t2);
            t0.norm(); //y^2-9bz^2
            y3.mul(t0);
            y3.add(x3); //(y^2+3z*2)(y^2-9z^2)+3b.z^2.8y^2
            t1.copy(this.x);
            t1.mul(iy); //
            this.x.copy(t0);
            this.x.norm();
            this.x.mul(t1);
            this.x.add(this.x); //(y^2-9bz^2)xy2

            this.x.norm();
            this.y.copy(y3);
            this.y.norm();

            return 1;
        },

        /* this+=Q - return 0 for add, 1 for double, -1 for O */
        /* this+=Q */
        add: function(Q) {
            var b, t0, t1, t2, t3, t4, x3, y3, z3;

            if (this.INF) {
                this.copy(Q);
                return -1;
            }

            if (Q.INF) {
                return -1;
            }

            b = 3 * ctx.ROM_CURVE.CURVE_B_I;
            t0 = new ctx.FP2(0);
            t0.copy(this.x); //FP2 t0=new FP2(x);
            t0.mul(Q.x); // x.Q.x
            t1 = new ctx.FP2(0);
            t1.copy(this.y); //FP2 t1=new FP2(y);
            t1.mul(Q.y); // y.Q.y

            t2 = new ctx.FP2(0);
            t2.copy(this.z); //FP2 t2=new FP2(z);
            t2.mul(Q.z);
            t3 = new ctx.FP2(0);
            t3.copy(this.x); //FP2 t3=new FP2(x);
            t3.add(this.y);
            t3.norm(); //t3=X1+Y1
            t4 = new ctx.FP2(0);
            t4.copy(Q.x); //FP2 t4=new FP2(Q.x);
            t4.add(Q.y);
            t4.norm(); //t4=X2+Y2
            t3.mul(t4); //t3=(X1+Y1)(X2+Y2)
            t4.copy(t0);
            t4.add(t1); //t4=X1.X2+Y1.Y2

            t3.sub(t4);
            t3.norm();
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                t3.mul_ip();
                t3.norm(); //t3=(X1+Y1)(X2+Y2)-(X1.X2+Y1.Y2) = X1.Y2+X2.Y1
            }

            t4.copy(this.y);
            t4.add(this.z);
            t4.norm(); //t4=Y1+Z1
            x3 = new ctx.FP2(0);
            x3.copy(Q.y); //FP2 x3=new FP2(Q.y);
            x3.add(Q.z);
            x3.norm(); //x3=Y2+Z2

            t4.mul(x3); //t4=(Y1+Z1)(Y2+Z2)
            x3.copy(t1); //
            x3.add(t2); //X3=Y1.Y2+Z1.Z2

            t4.sub(x3);
            t4.norm();
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                t4.mul_ip();
                t4.norm(); //t4=(Y1+Z1)(Y2+Z2) - (Y1.Y2+Z1.Z2) = Y1.Z2+Y2.Z1
            }

            x3.copy(this.x);
            x3.add(this.z);
            x3.norm(); // x3=X1+Z1
            y3 = new ctx.FP2(0);
            y3.copy(Q.x); //FP2 y3=new FP2(Q.x);
            y3.add(Q.z);
            y3.norm(); // y3=X2+Z2
            x3.mul(y3); // x3=(X1+Z1)(X2+Z2)
            y3.copy(t0);
            y3.add(t2); // y3=X1.X2+Z1+Z2
            y3.rsub(x3);
            y3.norm(); // y3=(X1+Z1)(X2+Z2) - (X1.X2+Z1.Z2) = X1.Z2+X2.Z1

            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                t0.mul_ip();
                t0.norm(); // x.Q.x
                t1.mul_ip();
                t1.norm(); // y.Q.y
            }

            x3.copy(t0);
            x3.add(t0);
            t0.add(x3);
            t0.norm();
            t2.imul(b);
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                t2.mul_ip();
            }

            z3 = new ctx.FP2(0);
            z3.copy(t1); //FP2 z3=new FP2(t1);
            z3.add(t2);
            z3.norm();
            t1.sub(t2);
            t1.norm();
            y3.imul(b);
            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                y3.mul_ip();
                y3.norm();
            }

            x3.copy(y3);
            x3.mul(t4);
            t2.copy(t3);
            t2.mul(t1);
            x3.rsub(t2);
            y3.mul(t0);
            t1.mul(z3);
            y3.add(t1);
            t0.mul(t3);
            z3.mul(t4);
            z3.add(t0);

            this.x.copy(x3);
            this.x.norm();
            this.y.copy(y3);
            this.y.norm();
            this.z.copy(z3);
            this.z.norm();

            return 0;
        },

        /* this-=Q */
        sub: function(Q) {
            var D;

            Q.neg();
            D = this.add(Q);
            Q.neg();

            return D;
        },

        /* P*=e */
        mul: function(e) {
            /* fixed size windows */
            var mt = new ctx.BIG(),
                t = new ctx.BIG(),
                C = new ECP2(),
                P = new ECP2(),
                Q = new ECP2(),
                W = [],
                w = [],
                i, nb, s, ns;

            if (this.is_infinity()) {
                return new ECP2();
            }

            this.affine();

            // precompute table
            Q.copy(this);
            Q.dbl();
            W[0] = new ECP2();
            W[0].copy(this);

            for (i = 1; i < 8; i++) {
                W[i] = new ECP2();
                W[i].copy(W[i - 1]);
                W[i].add(Q);
            }

            // make exponent odd - add 2P if even, P if odd
            t.copy(e);
            s = t.parity();
            t.inc(1);
            t.norm();
            ns = t.parity();
            mt.copy(t);
            mt.inc(1);
            mt.norm();
            t.cmove(mt, s);
            Q.cmove(this, ns);
            C.copy(Q);

            nb = 1 + Math.floor((t.nbits() + 3) / 4);

            // convert exponent to signed 4-bit window
            for (i = 0; i < nb; i++) {
                w[i] = (t.lastbits(5) - 16);
                t.dec(w[i]);
                t.norm();
                t.fshr(4);
            }
            w[nb] = t.lastbits(5);

            P.copy(W[Math.floor((w[nb] - 1) / 2)]);
            for (i = nb - 1; i >= 0; i--) {
                Q.select(W, w[i]);
                P.dbl();
                P.dbl();
                P.dbl();
                P.dbl();
                P.add(Q);
            }
            P.sub(C);
            P.affine();

            return P;
        }
    };

    /* convert from byte array to point */
    ECP2.fromBytes = function(b) {
        var t = [],
            ra, rb, i, rx, ry, P;

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i];
        }
        ra = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + ctx.BIG.MODBYTES];
        }
        rb = ctx.BIG.fromBytes(t);

        rx = new ctx.FP2(ra, rb); //rx.bset(ra,rb);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + 2 * ctx.BIG.MODBYTES];
        }
        ra = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + 3 * ctx.BIG.MODBYTES];
        }
        rb = ctx.BIG.fromBytes(t);

        ry = new ctx.FP2(ra, rb); //ry.bset(ra,rb);

        P = new ECP2();
        P.setxy(rx, ry);

        return P;
    };

    /* Calculate RHS of curve equation x^3+B */
    ECP2.RHS = function(x) {
        var r, c, b;

        x.norm();
        r = new ctx.FP2(x); //r.copy(x);
        r.sqr();

        c = new ctx.BIG(0);
        c.rcopy(ctx.ROM_CURVE.CURVE_B);
        b = new ctx.FP2(c); //b.bseta(c);

        if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
            b.div_ip();
        }
        if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
            b.norm();
            b.mul_ip();
            b.norm();
        }

        r.mul(x);
        r.add(b);

        r.reduce();

        return r;
    };

    /* P=u0.Q0+u1*Q1+u2*Q2+u3*Q3 */
    ECP2.mul4 = function(Q, u) {
        var a = [],
            T = new ECP2(),
            C = new ECP2(),
            P = new ECP2(),
            W = [],
            mt = new ctx.BIG(),
            t = [],
            w = [],
            i, j, nb;

        for (i = 0; i < 4; i++) {
            t[i] = new ctx.BIG(u[i]);
            Q[i].affine();
        }

        /* precompute table */

        W[0] = new ECP2();
        W[0].copy(Q[0]);
        W[0].sub(Q[1]);
        W[1] = new ECP2();
        W[1].copy(W[0]);
        W[2] = new ECP2();
        W[2].copy(W[0]);
        W[3] = new ECP2();
        W[3].copy(W[0]);
        W[4] = new ECP2();
        W[4].copy(Q[0]);
        W[4].add(Q[1]);
        W[5] = new ECP2();
        W[5].copy(W[4]);
        W[6] = new ECP2();
        W[6].copy(W[4]);
        W[7] = new ECP2();
        W[7].copy(W[4]);
        T.copy(Q[2]);
        T.sub(Q[3]);
        W[1].sub(T);
        W[2].add(T);
        W[5].sub(T);
        W[6].add(T);
        T.copy(Q[2]);
        T.add(Q[3]);
        W[0].sub(T);
        W[3].add(T);
        W[4].sub(T);
        W[7].add(T);

        /* if multiplier is even add 1 to multiplier, and add P to correction */
        mt.zero();
        C.inf();

        for (i = 0; i < 4; i++) {
            if (t[i].parity() == 0) {
                t[i].inc(1);
                t[i].norm();
                C.add(Q[i]);
            }
            mt.add(t[i]);
            mt.norm();
        }

        nb = 1 + mt.nbits();

        /* convert exponent to signed 1-bit window */
        for (j = 0; j < nb; j++) {
            for (i = 0; i < 4; i++) {
                a[i] = (t[i].lastbits(2) - 2);
                t[i].dec(a[i]);
                t[i].norm();
                t[i].fshr(1);
            }
            w[j] = (8 * a[0] + 4 * a[1] + 2 * a[2] + a[3]);
        }
        w[nb] = (8 * t[0].lastbits(2) + 4 * t[1].lastbits(2) + 2 * t[2].lastbits(2) + t[3].lastbits(2));

        P.copy(W[Math.floor((w[nb] - 1) / 2)]);

        for (i = nb - 1; i >= 0; i--) {
            T.select(W, w[i]);
            P.dbl();
            P.add(T);
        }
        P.sub(C); /* apply correction */

        P.affine();

        return P;
    };

    /* return 1 if b==c, no branching */
    ECP2.teq = function(b, c) {
        var x = b ^ c;
        x -= 1; // if x=0, x now -1
        return ((x >> 31) & 1);
    };

    /* needed for SOK */
    ECP2.mapit = function(h) {
        var q, x, one, Q, T, K, X, xQ, x2Q, Fa, Fb;

        q = new ctx.BIG(0);
        q.rcopy(ctx.ROM_FIELD.Modulus);
        x = ctx.BIG.fromBytes(h);
        one = new ctx.BIG(1);
        x.mod(q);

        for (;;) {
            X = new ctx.FP2(one, x);
            Q = new ECP2();
            Q.setx(X);
            if (!Q.is_infinity()) {
                break;
            }
            x.inc(1);
            x.norm();
        }
        /* Fast Hashing to G2 - Fuentes-Castaneda, Knapp and Rodriguez-Henriquez */

        Fa = new ctx.BIG(0);
        Fa.rcopy(ctx.ROM_FIELD.Fra);
        Fb = new ctx.BIG(0);
        Fb.rcopy(ctx.ROM_FIELD.Frb);
        X = new ctx.FP2(Fa, Fb);
        if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
            X.inverse();
            X.norm();
        }

        x = new ctx.BIG(0);
        x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);

        if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BN) {
            T = new ECP2();
            T.copy(Q);
            T = T.mul(x);
            if (ctx.ECP.SIGN_OF_X == ctx.ECP.NEGATIVEX) {
                T.neg();
            }
            K = new ECP2();
            K.copy(T);
            K.dbl();
            K.add(T); //K.affine();

            K.frob(X);
            Q.frob(X);
            Q.frob(X);
            Q.frob(X);
            Q.add(T);
            Q.add(K);
            T.frob(X);
            T.frob(X);
            Q.add(T);
        }

        if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BLS) {
            xQ = new ECP2();
            x2Q = new ECP2();

            xQ = Q.mul(x);
            x2Q = xQ.mul(x);

            if (ctx.ECP.SIGN_OF_X == ctx.ECP.NEGATIVEX) {
                xQ.neg();
            }

            x2Q.sub(xQ);
            x2Q.sub(Q);

            xQ.sub(Q);
            xQ.frob(X);

            Q.dbl();
            Q.frob(X);
            Q.frob(X);

            Q.add(x2Q);
            Q.add(xQ);
        }

        Q.affine();

        return Q;
    };

    return ECP2;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports.ECP2 = ECP2;
}

},{}],"./ecp":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* Elliptic Curve Point class */

var ECP = function(ctx) {
    "use strict";

    /* Constructor */
    var ECP = function() {
        this.x = new ctx.FP(0);
        this.y = new ctx.FP(1);
        this.z = new ctx.FP(0);
        this.INF = true;
    };

    ECP.WEIERSTRASS = 0;
    ECP.EDWARDS = 1;
    ECP.MONTGOMERY = 2;
    ECP.NOT = 0;
    ECP.BN = 1;
    ECP.BLS = 2;
    ECP.D_TYPE = 0;
    ECP.M_TYPE = 1;
    ECP.POSITIVEX = 0;
    ECP.NEGATIVEX = 1;

    ECP.CURVETYPE = ctx.config["@CT"];
    ECP.CURVE_PAIRING_TYPE = ctx.config["@PF"];
    ECP.SEXTIC_TWIST = ctx.config["@ST"];
    ECP.SIGN_OF_X = ctx.config["@SX"];

    ECP.prototype = {
        /* test this=O point-at-infinity */
        is_infinity: function() {
            if (this.INF) {
                return true;
            }

            this.x.reduce();
            this.z.reduce();

            if (ECP.CURVETYPE == ECP.EDWARDS) {
                this.y.reduce();
                this.INF = (this.x.iszilch() && this.y.equals(this.z));
            } else if (ECP.CURVETYPE == ECP.WEIERSTRASS) {
                this.y.reduce();
                this.INF = (this.x.iszilch() && this.z.iszilch());
            } else if (ECP.CURVETYPE == ECP.MONTGOMERY) {
                this.INF = (this.z.iszilch());
            }

            return this.INF;
        },

        /* conditional swap of this and Q dependant on d */
        cswap: function(Q, d) {
            var bd;

            this.x.cswap(Q.x, d);
            if (ECP.CURVETYPE != ECP.MONTGOMERY) {
                this.y.cswap(Q.y, d);
            }
            this.z.cswap(Q.z, d);

            bd = (d !== 0) ? true : false;
            bd = bd & (this.INF ^ Q.INF);
            this.INF ^= bd;
            Q.INF ^= bd;

        },

        /* conditional move of Q to P dependant on d */
        cmove: function(Q, d) {
            var bd;

            this.x.cmove(Q.x, d);
            if (ECP.CURVETYPE != ECP.MONTGOMERY) {
                this.y.cmove(Q.y, d);
            }
            this.z.cmove(Q.z, d);

            bd = (d !== 0) ? true : false;
            this.INF ^= (this.INF ^ Q.INF) & bd;
        },

        /* Constant time select from pre-computed table */
        select: function(W, b) {
            var MP = new ECP(),
                m = b >> 31,
                babs = (b ^ m) - m;

            babs = (babs - 1) / 2;

            this.cmove(W[0], ECP.teq(babs, 0)); // conditional move
            this.cmove(W[1], ECP.teq(babs, 1));
            this.cmove(W[2], ECP.teq(babs, 2));
            this.cmove(W[3], ECP.teq(babs, 3));
            this.cmove(W[4], ECP.teq(babs, 4));
            this.cmove(W[5], ECP.teq(babs, 5));
            this.cmove(W[6], ECP.teq(babs, 6));
            this.cmove(W[7], ECP.teq(babs, 7));

            MP.copy(this);
            MP.neg();
            this.cmove(MP, (m & 1));
        },

        /* Test P == Q */

        equals: function(Q) {
            var a, b;

            if (this.is_infinity() && Q.is_infinity()) {
                return true;
            }

            if (this.is_infinity() || Q.is_infinity()) {
                return false;
            }

            a = new ctx.FP(0);
            b = new ctx.FP(0);
            a.copy(this.x);
            a.mul(Q.z);
            a.reduce();
            b.copy(Q.x);
            b.mul(this.z);
            b.reduce();

            if (!a.equals(b)) {
                return false;
            }

            if (ECP.CURVETYPE != ECP.MONTGOMERY) {
                a.copy(this.y);
                a.mul(Q.z);
                a.reduce();
                b.copy(Q.y);
                b.mul(this.z);
                b.reduce();
                if (!a.equals(b)) {
                    return false;
                }
            }

            return true;
        },

        /* copy this=P */
        copy: function(P) {
            this.x.copy(P.x);
            if (ECP.CURVETYPE != ECP.MONTGOMERY) {
                this.y.copy(P.y);
            }
            this.z.copy(P.z);
            this.INF = P.INF;
        },

        /* this=-this */
        neg: function() {
            //      if (this.is_infinity()) return;
            if (ECP.CURVETYPE == ECP.WEIERSTRASS) {
                this.y.neg();
                this.y.norm();
            } else if (ECP.CURVETYPE == ECP.EDWARDS) {
                this.x.neg();
                this.x.norm();
            }

            return;
        },

        /* set this=O */
        inf: function() {
            this.INF = true;
            this.x.zero();

            if (ECP.CURVETYPE != ECP.MONTGOMERY) {
                this.y.one();
            }

            if (ECP.CURVETYPE != ECP.EDWARDS) {
                this.z.zero();
            } else {
                this.z.one();
            }
        },

        /* set this=(x,y) where x and y are BIGs */
        setxy: function(ix, iy) {
            var rhs, y2;

            this.x = new ctx.FP(0);
            this.x.bcopy(ix);

            this.y = new ctx.FP(0);
            this.y.bcopy(iy);
            this.z = new ctx.FP(1);
            rhs = ECP.RHS(this.x);

            if (ECP.CURVETYPE == ECP.MONTGOMERY) {
                if (rhs.jacobi() == 1) {
                    this.INF = false;
                } else {
                    this.inf();
                }
            } else {
                y2 = new ctx.FP(0);
                y2.copy(this.y);
                y2.sqr();

                if (y2.equals(rhs)) {
                    this.INF = false;
                } else {
                    this.inf();
                }
            }
        },

        /* set this=x, where x is ctx.BIG, y is derived from sign s */
        setxi: function(ix, s) {
            var rhs, ny;

            this.x = new ctx.FP(0);
            this.x.bcopy(ix);
            rhs = ECP.RHS(this.x);
            this.z = new ctx.FP(1);

            if (rhs.jacobi() == 1) {
                ny = rhs.sqrt();
                if (ny.redc().parity() != s) {
                    ny.neg();
                }
                this.y = ny;
                this.INF = false;
            } else {
                this.inf();
            }
        },

        /* set this=x, y calculated from curve equation */
        setx: function(ix) {
            var rhs;

            this.x = new ctx.FP(0);
            this.x.bcopy(ix);
            rhs = ECP.RHS(this.x);
            this.z = new ctx.FP(1);

            if (rhs.jacobi() == 1) {
                if (ECP.CURVETYPE != ECP.MONTGOMERY) {
                    this.y = rhs.sqrt();
                }
                this.INF = false;
            } else {
                this.INF = true;
            }
        },

        /* set this to affine - from (x,y,z) to (x,y) */
        affine: function() {
            var one;

            if (this.is_infinity()) {
                return;
            }

            one = new ctx.FP(1);

            if (this.z.equals(one)) {
                return;
            }

            this.z.inverse();

            if (ECP.CURVETYPE == ECP.EDWARDS || ECP.CURVETYPE == ECP.WEIERSTRASS) {
                this.x.mul(this.z);
                this.x.reduce();
                this.y.mul(this.z);
                this.y.reduce();
                this.z = one;
            }
            if (ECP.CURVETYPE == ECP.MONTGOMERY) {
                this.x.mul(this.z);
                this.x.reduce();
                this.z = one;
            }
        },

        /* extract x as ctx.BIG */
        getX: function() {
            this.affine();
            return this.x.redc();
        },

        /* extract y as ctx.BIG */
        getY: function() {
            this.affine();
            return this.y.redc();
        },

        /* get sign of Y */
        getS: function() {
            this.affine();
            var y = this.getY();
            return y.parity();
        },

        /* extract x as ctx.FP */
        getx: function() {
            return this.x;
        },

        /* extract y as ctx.FP */
        gety: function() {
            return this.y;
        },

        /* extract z as ctx.FP */
        getz: function() {
            return this.z;
        },

        /* convert to byte array */
        toBytes: function(b) {
            var t = [],
                i;

            if (ECP.CURVETYPE != ECP.MONTGOMERY) {
                b[0] = 0x04;
            } else {
                b[0] = 0x02;
            }

            this.affine();
            this.x.redc().toBytes(t);

            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                b[i + 1] = t[i];
            }

            if (ECP.CURVETYPE != ECP.MONTGOMERY) {
                this.y.redc().toBytes(t);
                for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                    b[i + ctx.BIG.MODBYTES + 1] = t[i];
                }
            }
        },
        /* convert to hex string */
        toString: function() {
            if (this.is_infinity()) {
                return "infinity";
            }

            this.affine();

            if (ECP.CURVETYPE == ECP.MONTGOMERY) {
                return "(" + this.x.redc().toString() + ")";
            } else {
                return "(" + this.x.redc().toString() + "," + this.y.redc().toString() + ")";
            }
        },

        /* this+=this */
        dbl: function() {
            var t0, t1, t2, t3, x3, y3, z3, b,
                C, D, H, J,
                A, B, AA, BB;

            if (ECP.CURVETYPE == ECP.WEIERSTRASS) {
                if (this.INF) {
                    return;
                }

                if (ctx.ROM_CURVE.CURVE_A == 0) {
                    t0 = new ctx.FP(0);
                    t0.copy(this.y); //FP t0=new FP(y);                      /*** Change ***/    // Edits made
                    t0.sqr();
                    t1 = new ctx.FP(0);
                    t1.copy(this.y); //FP t1=new FP(y);
                    t1.mul(this.z);
                    t2 = new ctx.FP(0);
                    t2.copy(this.z); //FP t2=new FP(z);
                    t2.sqr();

                    this.z.copy(t0);
                    this.z.add(t0);
                    this.z.norm();
                    this.z.add(this.z);
                    this.z.add(this.z);
                    this.z.norm();

                    t2.imul(3 * ctx.ROM_CURVE.CURVE_B_I);

                    x3 = new ctx.FP(0);
                    x3.copy(t2); //FP x3=new FP(t2);
                    x3.mul(this.z);
                    y3 = new ctx.FP(0);
                    y3.copy(t0); //FP y3=new FP(t0);
                    y3.add(t2);
                    y3.norm();
                    this.z.mul(t1);
                    t1.copy(t2);
                    t1.add(t2);
                    t2.add(t1);
                    t0.sub(t2);
                    t0.norm();
                    y3.mul(t0);
                    y3.add(x3);
                    t1.copy(this.x);
                    t1.mul(this.y);
                    this.x.copy(t0);
                    this.x.norm();
                    this.x.mul(t1);
                    this.x.add(this.x);

                    this.x.norm();
                    this.y.copy(y3);
                    this.y.norm();
                } else {
                    t0 = new ctx.FP(0);
                    t0.copy(this.x); //FP t0=new FP(x);
                    t1 = new ctx.FP(0);
                    t1.copy(this.y); //FP t1=new FP(y);
                    t2 = new ctx.FP(0);
                    t2.copy(this.z); //FP t2=new FP(z);
                    t3 = new ctx.FP(0);
                    t3.copy(this.x); //FP t3=new FP(x);
                    z3 = new ctx.FP(0);
                    z3.copy(this.z); //FP z3=new FP(z);
                    y3 = new ctx.FP(0); //FP y3=new FP(0);
                    x3 = new ctx.FP(0); //FP x3=new FP(0);
                    b = new ctx.FP(0); //FP b=new FP(0);
                    //System.out.println("Into dbl");
                    if (ctx.ROM_CURVE.CURVE_B_I == 0) {
                        b.rcopy(ctx.ROM_CURVE.CURVE_B);
                    }
                    //System.out.println("b= "+b.toString());
                    t0.sqr(); //1    x^2
                    t1.sqr(); //2    y^2
                    t2.sqr(); //3

                    t3.mul(this.y); //4
                    t3.add(t3);
                    t3.norm(); //5
                    z3.mul(this.x); //6
                    z3.add(z3);
                    z3.norm(); //7
                    y3.copy(t2);

                    if (ctx.ROM_CURVE.CURVE_B_I == 0) {
                        y3.mul(b); //8
                    } else {
                        y3.imul(ctx.ROM_CURVE.CURVE_B_I);
                    }

                    y3.sub(z3); //y3.norm(); //9  ***
                    x3.copy(y3);
                    x3.add(y3);
                    x3.norm(); //10

                    y3.add(x3); //y3.norm();//11
                    x3.copy(t1);
                    x3.sub(y3);
                    x3.norm(); //12
                    y3.add(t1);
                    y3.norm(); //13
                    y3.mul(x3); //14
                    x3.mul(t3); //15
                    t3.copy(t2);
                    t3.add(t2); //t3.norm(); //16
                    t2.add(t3); //t2.norm(); //17

                    if (ctx.ROM_CURVE.CURVE_B_I == 0) {
                        z3.mul(b); //18
                    } else {
                        z3.imul(ctx.ROM_CURVE.CURVE_B_I);
                    }

                    z3.sub(t2); //z3.norm();//19
                    z3.sub(t0);
                    z3.norm(); //20  ***
                    t3.copy(z3);
                    t3.add(z3); //t3.norm();//21

                    z3.add(t3);
                    z3.norm(); //22
                    t3.copy(t0);
                    t3.add(t0); //t3.norm(); //23
                    t0.add(t3); //t0.norm();//24
                    t0.sub(t2);
                    t0.norm(); //25

                    t0.mul(z3); //26
                    y3.add(t0); //y3.norm();//27
                    t0.copy(this.y);
                    t0.mul(this.z); //28
                    t0.add(t0);
                    t0.norm(); //29
                    z3.mul(t0); //30
                    x3.sub(z3); //x3.norm();//31
                    t0.add(t0);
                    t0.norm(); //32
                    t1.add(t1);
                    t1.norm(); //33
                    z3.copy(t0);
                    z3.mul(t1); //34
                    //System.out.println("Out of dbl");
                    this.x.copy(x3);
                    this.x.norm();
                    this.y.copy(y3);
                    this.y.norm();
                    this.z.copy(z3);
                    this.z.norm();
                }
            }

            if (ECP.CURVETYPE == ECP.EDWARDS) {
                C = new ctx.FP(0);
                C.copy(this.x); //FP C=new FP(x);
                D = new ctx.FP(0);
                D.copy(this.y); //FP D=new FP(y);
                H = new ctx.FP(0);
                H.copy(this.z); //FP H=new FP(z);
                J = new ctx.FP(0); //FP J=new FP(0);
                //System.out.println("Into dbl");
                this.x.mul(this.y);
                this.x.add(this.x);
                this.x.norm();
                C.sqr();
                D.sqr();
                if (ctx.ROM_CURVE.CURVE_A == -1) {
                    C.neg();
                }

                this.y.copy(C);
                this.y.add(D);
                this.y.norm();
                H.sqr();
                H.add(H);

                this.z.copy(this.y);
                J.copy(this.y);

                J.sub(H);
                J.norm();

                this.x.mul(J);
                C.sub(D);
                C.norm();
                this.y.mul(C);
                this.z.mul(J);
                //System.out.println("Out of dbl");
            }

            if (ECP.CURVETYPE == ECP.MONTGOMERY) {
                A = new ctx.FP(0);
                A.copy(this.x); //FP A=new FP(x);
                B = new ctx.FP(0);
                B.copy(this.x); //FP B=new FP(x);
                AA = new ctx.FP(0); //FP AA=new FP(0);
                BB = new ctx.FP(0); //FP BB=new FP(0);
                C = new ctx.FP(0); //FP C=new FP(0);

                A.add(this.z);
                A.norm();
                AA.copy(A);
                AA.sqr();
                B.sub(this.z);
                B.norm();
                BB.copy(B);
                BB.sqr();
                C.copy(AA);
                C.sub(BB);
                C.norm();
                this.x.copy(AA);
                this.x.mul(BB);

                A.copy(C);
                A.imul((ctx.ROM_CURVE.CURVE_A + 2) >> 2);

                BB.add(A);
                BB.norm();
                this.z.copy(BB);
                this.z.mul(C);
            }

            return;
        },

        /* this+=Q */
        add: function(Q) {
            var b, t0, t1, t2, t3, t4, x3, y3, z3,
                A, B, C, D, E, F, G;

            if (this.INF) {
                this.copy(Q);
                return;
            }

            if (Q.INF) {
                return;
            }

            if (ECP.CURVETYPE == ECP.WEIERSTRASS) {
                //System.out.println("Into add");
                if (ctx.ROM_CURVE.CURVE_A == 0) {
                    //  System.out.println("Into add");                      // Edits made

                    b = 3 * ctx.ROM_CURVE.CURVE_B_I;
                    t0 = new ctx.FP(0);
                    t0.copy(this.x); //FP t0=new FP(x);
                    t0.mul(Q.x);
                    t1 = new ctx.FP(0);
                    t1.copy(this.y); //FP t1=new FP(y);
                    t1.mul(Q.y);
                    t2 = new ctx.FP(0);
                    t2.copy(this.z); //FP t2=new FP(z);
                    t2.mul(Q.z);
                    t3 = new ctx.FP(0);
                    t3.copy(this.x); //FP t3=new FP(x);
                    t3.add(this.y);
                    t3.norm();
                    t4 = new ctx.FP(0);
                    t4.copy(Q.x); //FP t4=new FP(Q.x);
                    t4.add(Q.y);
                    t4.norm();
                    t3.mul(t4);
                    t4.copy(t0);
                    t4.add(t1);

                    t3.sub(t4);
                    t3.norm();
                    t4.copy(this.y);
                    t4.add(this.z);
                    t4.norm();
                    x3 = new ctx.FP(0);
                    x3.copy(Q.y); //FP x3=new FP(Q.y);
                    x3.add(Q.z);
                    x3.norm();

                    t4.mul(x3);
                    x3.copy(t1);
                    x3.add(t2);

                    t4.sub(x3);
                    t4.norm();
                    x3.copy(this.x);
                    x3.add(this.z);
                    x3.norm();
                    y3 = new ctx.FP(0);
                    y3.copy(Q.x); //FP y3=new FP(Q.x);
                    y3.add(Q.z);
                    y3.norm();
                    x3.mul(y3);
                    y3.copy(t0);
                    y3.add(t2);
                    y3.rsub(x3);
                    y3.norm();
                    x3.copy(t0);
                    x3.add(t0);
                    t0.add(x3);
                    t0.norm();
                    t2.imul(b);

                    z3 = new ctx.FP(0);
                    z3.copy(t1); //FP z3=new FP(t1);
                    z3.add(t2);
                    z3.norm();
                    t1.sub(t2);
                    t1.norm();
                    y3.imul(b);

                    x3.copy(y3);
                    x3.mul(t4);
                    t2.copy(t3);
                    t2.mul(t1);
                    x3.rsub(t2);
                    y3.mul(t0);
                    t1.mul(z3);
                    y3.add(t1);
                    t0.mul(t3);
                    z3.mul(t4);
                    z3.add(t0);

                    //System.out.println("Out of add");

                    this.x.copy(x3);
                    this.x.norm();
                    this.y.copy(y3);
                    this.y.norm();
                    this.z.copy(z3);
                    this.z.norm();
                } else {
                    t0 = new ctx.FP(0);
                    t0.copy(this.x); //FP t0=new FP(x);
                    t1 = new ctx.FP(0);
                    t1.copy(this.y); //FP t1=new FP(y);
                    t2 = new ctx.FP(0);
                    t2.copy(this.z); //FP t2=new FP(z);
                    t3 = new ctx.FP(0);
                    t3.copy(this.x); //FP t3=new FP(x);
                    t4 = new ctx.FP(0);
                    t4.copy(Q.x); //FP t4=new FP(Q.x);
                    z3 = new ctx.FP(0); //FP z3=new FP(0);
                    y3 = new ctx.FP(0);
                    y3.copy(Q.x); //FP y3=new FP(Q.x);
                    x3 = new ctx.FP(0);
                    x3.copy(Q.y); //FP x3=new FP(Q.y);
                    b = new ctx.FP(0); //FP b=new FP(0);

                    if (ctx.ROM_CURVE.CURVE_B_I == 0) {
                        b.rcopy(ctx.ROM_CURVE.CURVE_B);
                    }
                    t0.mul(Q.x); //1
                    t1.mul(Q.y); //2
                    t2.mul(Q.z); //3

                    t3.add(this.y);
                    t3.norm(); //4
                    t4.add(Q.y);
                    t4.norm(); //5
                    t3.mul(t4); //6
                    t4.copy(t0);
                    t4.add(t1); //t4.norm(); //7
                    t3.sub(t4);
                    t3.norm(); //8
                    t4.copy(this.y);
                    t4.add(this.z);
                    t4.norm(); //9
                    x3.add(Q.z);
                    x3.norm(); //10
                    t4.mul(x3); //11
                    x3.copy(t1);
                    x3.add(t2); //x3.norm();//12

                    t4.sub(x3);
                    t4.norm(); //13
                    x3.copy(this.x);
                    x3.add(this.z);
                    x3.norm(); //14
                    y3.add(Q.z);
                    y3.norm(); //15

                    x3.mul(y3); //16
                    y3.copy(t0);
                    y3.add(t2); //y3.norm();//17

                    y3.rsub(x3);
                    y3.norm(); //18
                    z3.copy(t2);

                    if (ctx.ROM_CURVE.CURVE_B_I == 0) {
                        z3.mul(b); //18
                    } else {
                        z3.imul(ctx.ROM_CURVE.CURVE_B_I);
                    }

                    x3.copy(y3);
                    x3.sub(z3);
                    x3.norm(); //20
                    z3.copy(x3);
                    z3.add(x3); //z3.norm(); //21

                    x3.add(z3); //x3.norm(); //22
                    z3.copy(t1);
                    z3.sub(x3);
                    z3.norm(); //23
                    x3.add(t1);
                    x3.norm(); //24

                    if (ctx.ROM_CURVE.CURVE_B_I == 0) {
                        y3.mul(b); //18
                    } else {
                        y3.imul(ctx.ROM_CURVE.CURVE_B_I);
                    }

                    t1.copy(t2);
                    t1.add(t2); //t1.norm();//26
                    t2.add(t1); //t2.norm();//27

                    y3.sub(t2); //y3.norm(); //28

                    y3.sub(t0);
                    y3.norm(); //29
                    t1.copy(y3);
                    t1.add(y3); //t1.norm();//30
                    y3.add(t1);
                    y3.norm(); //31

                    t1.copy(t0);
                    t1.add(t0); //t1.norm(); //32
                    t0.add(t1); //t0.norm();//33
                    t0.sub(t2);
                    t0.norm(); //34
                    t1.copy(t4);
                    t1.mul(y3); //35
                    t2.copy(t0);
                    t2.mul(y3); //36
                    y3.copy(x3);
                    y3.mul(z3); //37
                    y3.add(t2); //y3.norm();//38
                    x3.mul(t3); //39
                    x3.sub(t1); //40
                    z3.mul(t4); //41
                    t1.copy(t3);
                    t1.mul(t0); //42
                    z3.add(t1); //z3.norm();
                    //System.out.println("Out of add");
                    this.x.copy(x3);
                    this.x.norm();
                    this.y.copy(y3);
                    this.y.norm();
                    this.z.copy(z3);
                    this.z.norm();
                }
            }

            if (ECP.CURVETYPE == ECP.EDWARDS) {
                A = new ctx.FP(0);
                A.copy(this.z); //FP A=new FP(z);
                B = new ctx.FP(0); //FP B=new FP(0);
                C = new ctx.FP(0);
                C.copy(this.x); //FP C=new FP(x);
                D = new ctx.FP(0);
                D.copy(this.y); //FP D=new FP(y);
                E = new ctx.FP(0); //FP E=new FP(0);
                F = new ctx.FP(0); //FP F=new FP(0);
                G = new ctx.FP(0); //FP G=new FP(0);

                A.mul(Q.z); //A=2
                B.copy(A);
                B.sqr(); //B=2
                C.mul(Q.x); //C=2
                D.mul(Q.y); //D=2

                E.copy(C);
                E.mul(D); //E=2

                if (ctx.ROM_CURVE.CURVE_B_I == 0) {
                    b = new ctx.FP(0);
                    b.rcopy(ctx.ROM_CURVE.CURVE_B);
                    E.mul(b);
                } else {
                    E.imul(ctx.ROM_CURVE.CURVE_B_I); //E=22222
                }

                F.copy(B);
                F.sub(E); //F=22224
                G.copy(B);
                G.add(E); //G=22224

                if (ctx.ROM_CURVE.CURVE_A == 1) {
                    E.copy(D);
                    E.sub(C); //E=4
                }
                C.add(D); //C=4

                B.copy(this.x);
                B.add(this.y); //B=4
                D.copy(Q.x);
                D.add(Q.y);
                B.norm();
                D.norm(); //D=4
                B.mul(D); //B=2
                B.sub(C);
                B.norm();
                F.norm(); // B=6
                B.mul(F); //B=2
                this.x.copy(A);
                this.x.mul(B);
                G.norm(); // x=2

                if (ctx.ROM_CURVE.CURVE_A == 1) {
                    E.norm();
                    C.copy(E);
                    C.mul(G); //C=2
                }

                if (ctx.ROM_CURVE.CURVE_A == -1) {
                    C.norm();
                    C.mul(G);
                }

                this.y.copy(A);
                this.y.mul(C); //y=2
                this.z.copy(F);
                this.z.mul(G);
            }

            return;
        },

        /* Differential Add for Montgomery curves. this+=Q where W is this-Q and is affine. */
        dadd: function(Q, W) {
            var A, B, C, D, DA, CB;

            A = new ctx.FP(0);
            A.copy(this.x);
            B = new ctx.FP(0);
            B.copy(this.x);
            C = new ctx.FP(0);
            C.copy(Q.x);
            D = new ctx.FP(0);
            D.copy(Q.x);
            DA = new ctx.FP(0);
            CB = new ctx.FP(0);

            A.add(this.z);
            B.sub(this.z);

            C.add(Q.z);
            D.sub(Q.z);

            D.norm();
            A.norm();
            DA.copy(D);
            DA.mul(A);
            C.norm();
            B.norm();
            CB.copy(C);
            CB.mul(B);

            A.copy(DA);
            A.add(CB);
            A.norm();
            A.sqr();
            B.copy(DA);
            B.sub(CB);
            B.norm();
            B.sqr();

            this.x.copy(A);
            this.z.copy(W.x);
            this.z.mul(B);

            //  this.x.norm();
        },

        /* this-=Q */
        sub: function(Q) {
            Q.neg();
            this.add(Q);
            Q.neg();
        },

        /* constant time multiply by small integer of length bts - use ladder */
        pinmul: function(e, bts) {
            var i, b, P, R0, R1;

            if (ECP.CURVETYPE == ECP.MONTGOMERY) {
                return this.mul(new ctx.BIG(e));
            } else {
                P = new ECP();
                R0 = new ECP();
                R1 = new ECP();
                R1.copy(this);

                for (i = bts - 1; i >= 0; i--) {
                    b = (e >> i) & 1;
                    P.copy(R1);
                    P.add(R0);
                    R0.cswap(R1, b);
                    R1.copy(P);
                    R0.dbl();
                    R0.cswap(R1, b);
                }

                P.copy(R0);
                P.affine();

                return P;
            }
        },

        /* return e.this - SPA immune, using Ladder */

        mul: function(e) {
            var P, D, R0, R1, mt, t, Q, C, W, w,
                i, b, nb, s, ns;

            if (e.iszilch() || this.is_infinity()) {
                return new ECP();
            }

            P = new ECP();

            if (ECP.CURVETYPE == ECP.MONTGOMERY) { /* use ladder */
                D = new ECP();
                R0 = new ECP();
                R0.copy(this);
                R1 = new ECP();
                R1.copy(this);
                R1.dbl();
                D.copy(this);
                D.affine();
                nb = e.nbits();
                for (i = nb - 2; i >= 0; i--) {
                    b = e.bit(i);
                    P.copy(R1);
                    P.dadd(R0, D);

                    R0.cswap(R1, b);
                    R1.copy(P);
                    R0.dbl();
                    R0.cswap(R1, b);
                }
                P.copy(R0);
            } else {
                // fixed size windows
                mt = new ctx.BIG();
                t = new ctx.BIG();
                Q = new ECP();
                C = new ECP();
                W = [];
                w = [];

                this.affine();

                // precompute table
                Q.copy(this);
                Q.dbl();
                W[0] = new ECP();
                W[0].copy(this);

                for (i = 1; i < 8; i++) {
                    W[i] = new ECP();
                    W[i].copy(W[i - 1]);
                    W[i].add(Q);
                }

                // make exponent odd - add 2P if even, P if odd
                t.copy(e);
                s = t.parity();
                t.inc(1);
                t.norm();
                ns = t.parity();
                mt.copy(t);
                mt.inc(1);
                mt.norm();
                t.cmove(mt, s);
                Q.cmove(this, ns);
                C.copy(Q);

                nb = 1 + Math.floor((t.nbits() + 3) / 4);

                // convert exponent to signed 4-bit window
                for (i = 0; i < nb; i++) {
                    w[i] = (t.lastbits(5) - 16);
                    t.dec(w[i]);
                    t.norm();
                    t.fshr(4);
                }
                w[nb] = t.lastbits(5);

                P.copy(W[Math.floor((w[nb] - 1) / 2)]);
                for (i = nb - 1; i >= 0; i--) {
                    Q.select(W, w[i]);
                    P.dbl();
                    P.dbl();
                    P.dbl();
                    P.dbl();
                    P.add(Q);
                }
                P.sub(C);
            }

            P.affine();

            return P;
        },

        /* Return e.this+f.Q */

        mul2: function(e, Q, f) {
            var te = new ctx.BIG(),
                tf = new ctx.BIG(),
                mt = new ctx.BIG(),
                S = new ECP(),
                T = new ECP(),
                C = new ECP(),
                W = [],
                w = [],
                i, s, ns, nb,
                a, b;

            this.affine();
            Q.affine();

            te.copy(e);
            tf.copy(f);

            // precompute table
            W[1] = new ECP();
            W[1].copy(this);
            W[1].sub(Q);
            W[2] = new ECP();
            W[2].copy(this);
            W[2].add(Q);
            S.copy(Q);
            S.dbl();
            W[0] = new ECP();
            W[0].copy(W[1]);
            W[0].sub(S);
            W[3] = new ECP();
            W[3].copy(W[2]);
            W[3].add(S);
            T.copy(this);
            T.dbl();
            W[5] = new ECP();
            W[5].copy(W[1]);
            W[5].add(T);
            W[6] = new ECP();
            W[6].copy(W[2]);
            W[6].add(T);
            W[4] = new ECP();
            W[4].copy(W[5]);
            W[4].sub(S);
            W[7] = new ECP();
            W[7].copy(W[6]);
            W[7].add(S);

            // if multiplier is odd, add 2, else add 1 to multiplier, and add 2P or P to correction

            s = te.parity();
            te.inc(1);
            te.norm();
            ns = te.parity();
            mt.copy(te);
            mt.inc(1);
            mt.norm();
            te.cmove(mt, s);
            T.cmove(this, ns);
            C.copy(T);

            s = tf.parity();
            tf.inc(1);
            tf.norm();
            ns = tf.parity();
            mt.copy(tf);
            mt.inc(1);
            mt.norm();
            tf.cmove(mt, s);
            S.cmove(Q, ns);
            C.add(S);

            mt.copy(te);
            mt.add(tf);
            mt.norm();
            nb = 1 + Math.floor((mt.nbits() + 1) / 2);

            // convert exponent to signed 2-bit window
            for (i = 0; i < nb; i++) {
                a = (te.lastbits(3) - 4);
                te.dec(a);
                te.norm();
                te.fshr(2);
                b = (tf.lastbits(3) - 4);
                tf.dec(b);
                tf.norm();
                tf.fshr(2);
                w[i] = (4 * a + b);
            }
            w[nb] = (4 * te.lastbits(3) + tf.lastbits(3));
            S.copy(W[Math.floor((w[nb] - 1) / 2)]);

            for (i = nb - 1; i >= 0; i--) {
                T.select(W, w[i]);
                S.dbl();
                S.dbl();
                S.add(T);
            }
            S.sub(C); /* apply correction */
            S.affine();

            return S;
        }
    };

    /* return 1 if b==c, no branching */
    ECP.teq = function(b, c) {
        var x = b ^ c;
        x -= 1; // if x=0, x now -1
        return ((x >> 31) & 1);
    };

    /* convert from byte array to ECP */
    ECP.fromBytes = function(b) {
        var t = [],
            P = new ECP(),
            p = new ctx.BIG(0),
            px, py, i;

        p.rcopy(ctx.ROM_FIELD.Modulus);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = b[i + 1];
        }

        px = ctx.BIG.fromBytes(t);
        if (ctx.BIG.comp(px, p) >= 0) {
            return P;
        }

        if (b[0] == 0x04) {
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                t[i] = b[i + ctx.BIG.MODBYTES + 1];
            }

            py = ctx.BIG.fromBytes(t);

            if (ctx.BIG.comp(py, p) >= 0) {
                return P;
            }

            P.setxy(px, py);

            return P;
        } else {
            P.setx(px);
            return P;
        }
    };

    /* Calculate RHS of curve equation */
    ECP.RHS = function(x) {
        var r = new ctx.FP(0),
            b, cx, one, x3;

        x.norm();
        r.copy(x);
        r.sqr();

        if (ECP.CURVETYPE == ECP.WEIERSTRASS) { // x^3+Ax+B
            b = new ctx.FP(0);
            b.rcopy(ctx.ROM_CURVE.CURVE_B);
            r.mul(x);
            if (ctx.ROM_CURVE.CURVE_A == -3) {
                cx = new ctx.FP(0);
                cx.copy(x);
                cx.imul(3);
                cx.neg();
                cx.norm();
                r.add(cx);
            }
            r.add(b);
        } else if (ECP.CURVETYPE == ECP.EDWARDS) { // (Ax^2-1)/(Bx^2-1)
            b = new ctx.FP(0);
            b.rcopy(ctx.ROM_CURVE.CURVE_B);

            one = new ctx.FP(1);
            b.mul(r);
            b.sub(one);
            if (ctx.ROM_CURVE.CURVE_A == -1) {
                r.neg();
            }
            r.sub(one);
            r.norm();
            b.inverse();

            r.mul(b);
        } else if (ECP.CURVETYPE == ECP.MONTGOMERY) { // x^3+Ax^2+x
            x3 = new ctx.FP(0);
            x3.copy(r);
            x3.mul(x);
            r.imul(ctx.ROM_CURVE.CURVE_A);
            r.add(x3);
            r.add(x);
        }

        r.reduce();

        return r;
    };

    ECP.mapit = function(h) {
        var q = new ctx.BIG(0),
            x = ctx.BIG.fromBytes(h),
            P = new ECP(),
            c;

        q.rcopy(ctx.ROM_FIELD.Modulus);
        x.mod(q);

        for (;;) {
            P.setxi(x, 0);
            if (!P.is_infinity()) {
                break;
            }
            x.inc(1);
            x.norm();
        }

        if (ECP.CURVE_PAIRING_TYPE != ECP.BN) {
            c = new ctx.BIG(0);
            c.rcopy(ctx.ROM_CURVE.CURVE_Cof);
            P = P.mul(c);
        }

        return P;
    };

    return ECP;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports.ECP = ECP;
}

},{}],"./ff":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* AMCL FF number class */

var FF = function(ctx) {
    "use strict";

    /* General purpose Constructor */
    var FF = function(n) {
        this.v = new Array(n);
        this.length = n;
        for (var i = 0; i < n; i++) {
            this.v[i] = new ctx.BIG(0);
        }
    };

    FF.FFLEN = ctx.config["@ML"];
    FF.P_MBITS = ctx.BIG.MODBYTES * 8;
    FF.P_OMASK = ((-1) << (FF.P_MBITS % ctx.BIG.BASEBITS));
    FF.P_FEXCESS = (1 << (ctx.BIG.BASEBITS * ctx.BIG.NLEN - FF.P_MBITS - 1));
    FF.P_TBITS = (FF.P_MBITS % ctx.BIG.BASEBITS);
    FF.FF_BITS = (ctx.BIG.BIGBITS * FF.FFLEN);
    FF.HFLEN = (FF.FFLEN / 2); /* Useful for half-size RSA private key operations */

    FF.prototype = {
        /* set to zero */

        P_EXCESS: function() {
            return ((this.v[this.length - 1].get(ctx.BIG.NLEN - 1) & FF.P_OMASK) >> (FF.P_TBITS)) + 1;
        },

        zero: function() {
            for (var i = 0; i < this.length; i++) {
                this.v[i].zero();
            }

            return this;
        },

        getlen: function() {
            return this.length;
        },

        /* set to integer */
        set: function(m) {
            this.zero();
            this.v[0].set(0, (m & ctx.BIG.BMASK));
            this.v[0].set(1, (m >> ctx.BIG.BASEBITS));
        },
        /* copy from FF b */
        copy: function(b) {
            for (var i = 0; i < this.length; i++) {
                this.v[i].copy(b.v[i]);
            }
        },
        /* copy from FF b */
        rcopy: function(b) {
            for (var i = 0; i < this.length; i++) {
                this.v[i].rcopy(b[i]);
            }
        },
        /* x=y<<n */
        dsucopy: function(b) {
            for (var i = 0; i < b.length; i++) {
                this.v[b.length + i].copy(b.v[i]);
                this.v[i].zero();
            }
        },
        /* x=y */
        dscopy: function(b) {
            for (var i = 0; i < b.length; i++) {
                this.v[i].copy(b.v[i]);
                this.v[b.length + i].zero();
            }
        },

        /* x=y>>n */
        sducopy: function(b) {
            for (var i = 0; i < this.length; i++) {
                this.v[i].copy(b.v[this.length + i]);
            }
        },
        one: function() {
            this.v[0].one();
            for (var i = 1; i < this.length; i++) {
                this.v[i].zero();
            }
        },
        /* test equals 0 */
        iszilch: function() {
            for (var i = 0; i < this.length; i++) {
                if (!this.v[i].iszilch()) {
                    return false;
                }
            }

            return true;
        },
        /* shift right by BIGBITS-bit words */
        shrw: function(n) {
            for (var i = 0; i < n; i++) {
                this.v[i].copy(this.v[i + n]);
                this.v[i + n].zero();
            }
        },

        /* shift left by BIGBITS-bit words */
        shlw: function(n) {
            for (var i = 0; i < n; i++) {
                this.v[n + i].copy(this.v[i]);
                this.v[i].zero();
            }
        },
        /* extract last bit */
        parity: function() {
            return this.v[0].parity();
        },

        lastbits: function(m) {
            return this.v[0].lastbits(m);
        },

        /* recursive add */
        radd: function(vp, x, xp, y, yp, n) {
            for (var i = 0; i < n; i++) {
                this.v[vp + i].copy(x.v[xp + i]);
                this.v[vp + i].add(y.v[yp + i]);
            }
        },

        /* recursive inc */
        rinc: function(vp, y, yp, n) {
            for (var i = 0; i < n; i++) {
                this.v[vp + i].add(y.v[yp + i]);
            }
        },

        /* recursive sub */
        rsub: function(vp, x, xp, y, yp, n) {
            for (var i = 0; i < n; i++) {
                this.v[vp + i].copy(x.v[xp + i]);
                this.v[vp + i].sub(y.v[yp + i]);
            }
        },

        /* recursive dec */
        rdec: function(vp, y, yp, n) {
            for (var i = 0; i < n; i++) {
                this.v[vp + i].sub(y.v[yp + i]);
            }
        },

        /* simple add */
        add: function(b) {
            for (var i = 0; i < this.length; i++) {
                this.v[i].add(b.v[i]);
            }
        },

        /* simple sub */
        sub: function(b) {
            for (var i = 0; i < this.length; i++) {
                this.v[i].sub(b.v[i]);
            }
        },

        /* reverse sub */
        revsub: function(b) {
            for (var i = 0; i < this.length; i++) {
                this.v[i].rsub(b.v[i]);
            }
        },

        /* increment/decrement by a small integer */
        inc: function(m) {
            this.v[0].inc(m);
            this.norm();
        },

        dec: function(m) {
            this.v[0].dec(m);
            this.norm();
        },

        /* normalise - but hold any overflow in top part unless n<0 */
        rnorm: function(vp, n) {
            var trunc = false,
                i, carry;

            if (n < 0) { /* -v n signals to do truncation */
                n = -n;
                trunc = true;
            }

            for (i = 0; i < n - 1; i++) {
                carry = this.v[vp + i].norm();
                this.v[vp + i].xortop(carry << FF.P_TBITS);
                this.v[vp + i + 1].inc(carry);
            }
            carry = this.v[vp + n - 1].norm();

            if (trunc) {
                this.v[vp + n - 1].xortop(carry << FF.P_TBITS);
            }

            return this;
        },

        norm: function() {
            this.rnorm(0, this.length);
        },

        /* shift left by one bit */
        shl: function() {
            var delay_carry = 0,
                i, carry;

            for (i = 0; i < this.length - 1; i++) {
                carry = this.v[i].fshl(1);
                this.v[i].inc(delay_carry);
                this.v[i].xortop(carry << FF.P_TBITS);
                delay_carry = carry;
            }

            this.v[this.length - 1].fshl(1);
            this.v[this.length - 1].inc(delay_carry);
        },

        /* shift right by one bit */
        shr: function() {
            var i, carry;

            for (i = this.length - 1; i > 0; i--) {
                carry = this.v[i].fshr(1);
                this.v[i - 1].ortop(carry << FF.P_TBITS);
            }

            this.v[0].fshr(1);
        },

        /* Convert to Hex String */
        toString: function() {
            var s = "",
                i;

            this.norm();

            for (i = this.length - 1; i >= 0; i--) {
                s += this.v[i].toString();
            }

            return s;
        },
        /* Convert FFs to/from byte arrays */
        toBytes: function(b) {
            var i;

            for (i = 0; i < this.length; i++) {
                this.v[i].tobytearray(b, (this.length - i - 1) * ctx.BIG.MODBYTES);
            }
        },

        /* z=x*y, t is workspace */
        karmul: function(vp, x, xp, y, yp, t, tp, n) {
            var nd2, d;

            if (n === 1) {
                x.v[xp].norm();
                y.v[yp].norm();
                d = ctx.BIG.mul(x.v[xp], y.v[yp]);
                this.v[vp + 1] = d.split(8 * ctx.BIG.MODBYTES);
                this.v[vp].copy(d);

                return;
            }

            nd2 = n / 2;
            this.radd(vp, x, xp, x, xp + nd2, nd2);
            this.rnorm(vp, nd2); /* Important - required for 32-bit build */
            this.radd(vp + nd2, y, yp, y, yp + nd2, nd2);
            this.rnorm(vp + nd2, nd2); /* Important - required for 32-bit build */
            t.karmul(tp, this, vp, this, vp + nd2, t, tp + n, nd2);
            this.karmul(vp, x, xp, y, yp, t, tp + n, nd2);
            this.karmul(vp + n, x, xp + nd2, y, yp + nd2, t, tp + n, nd2);
            t.rdec(tp, this, vp, n);
            t.rdec(tp, this, vp + n, n);
            this.rinc(vp + nd2, t, tp, n);
            this.rnorm(vp, 2 * n);
        },

        karsqr: function(vp, x, xp, t, tp, n) {
            var nd2, d;

            if (n === 1) {
                x.v[xp].norm();
                d = ctx.BIG.sqr(x.v[xp]);
                this.v[vp + 1].copy(d.split(8 * ctx.BIG.MODBYTES));
                this.v[vp].copy(d);

                return;
            }

            nd2 = n / 2;
            this.karsqr(vp, x, xp, t, tp + n, nd2);
            this.karsqr(vp + n, x, xp + nd2, t, tp + n, nd2);
            t.karmul(tp, x, xp, x, xp + nd2, t, tp + n, nd2);
            this.rinc(vp + nd2, t, tp, n);
            this.rinc(vp + nd2, t, tp, n);
            this.rnorm(vp + nd2, n);
        },

        karmul_lower: function(vp, x, xp, y, yp, t, tp, n) { /* Calculates Least Significant bottom half of x*y */
            var nd2;

            if (n === 1) { /* only calculate bottom half of product */
                this.v[vp].copy(ctx.BIG.smul(x.v[xp], y.v[yp]));

                return;
            }

            nd2 = n / 2;

            this.karmul(vp, x, xp, y, yp, t, tp + n, nd2);
            t.karmul_lower(tp, x, xp + nd2, y, yp, t, tp + n, nd2);
            this.rinc(vp + nd2, t, tp, nd2);
            t.karmul_lower(tp, x, xp, y, yp + nd2, t, tp + n, nd2);

            this.rinc(vp + nd2, t, tp, nd2);
            this.rnorm(vp + nd2, -nd2); /* truncate it */
        },

        karmul_upper: function(x, y, t, n) { /* Calculates Most Significant upper half of x*y, given lower part */
            var nd2;

            nd2 = n / 2;
            this.radd(n, x, 0, x, nd2, nd2);
            this.radd(n + nd2, y, 0, y, nd2, nd2);
            this.rnorm(n, nd2);
            this.rnorm(n + nd2, nd2);

            t.karmul(0, this, n + nd2, this, n, t, n, nd2); /* t = (a0+a1)(b0+b1) */
            this.karmul(n, x, nd2, y, nd2, t, n, nd2); /* z[n]= a1*b1 */
            /* z[0-nd2]=l(a0b0) z[nd2-n]= h(a0b0)+l(t)-l(a0b0)-l(a1b1) */
            t.rdec(0, this, n, n); /* t=t-a1b1  */
            this.rinc(nd2, this, 0, nd2); /* z[nd2-n]+=l(a0b0) = h(a0b0)+l(t)-l(a1b1)  */
            this.rdec(nd2, t, 0, nd2); /* z[nd2-n]=h(a0b0)+l(t)-l(a1b1)-l(t-a1b1)=h(a0b0) */
            this.rnorm(0, -n); /* a0b0 now in z - truncate it */
            t.rdec(0, this, 0, n); /* (a0+a1)(b0+b1) - a0b0 */
            this.rinc(nd2, t, 0, n);

            this.rnorm(nd2, n);
        },

        /* return low part of product this*y */
        lmul: function(y) {
            var n = this.length,
                t = new FF(2 * n),
                x = new FF(n);

            x.copy(this);
            this.karmul_lower(0, x, 0, y, 0, t, 0, n);
        },

        /* Set b=b mod c */
        mod: function(c) {
            var k = 0;

            this.norm();
            if (FF.comp(this, c) < 0) {
                return;
            }

            do {
                c.shl();
                k++;
            } while (FF.comp(this, c) >= 0);

            while (k > 0) {
                c.shr();

                if (FF.comp(this, c) >= 0) {
                    this.sub(c);
                    this.norm();
                }

                k--;
            }
        },

        /* return This mod modulus, N is modulus, ND is Montgomery Constant */
        reduce: function(N, ND) { /* fast karatsuba Montgomery reduction */
            var n = N.length,
                t = new FF(2 * n),
                r = new FF(n),
                m = new FF(n);

            r.sducopy(this);
            m.karmul_lower(0, this, 0, ND, 0, t, 0, n);
            this.karmul_upper(N, m, t, n);
            m.sducopy(this);

            r.add(N);
            r.sub(m);
            r.norm();

            return r;
        },

        /* Set r=this mod b */
        /* this is of length - 2*n */
        /* r,b is of length - n */
        dmod: function(b) {
            var n = b.length,
                m = new FF(2 * n),
                x = new FF(2 * n),
                r = new FF(n),
                k;

            x.copy(this);
            x.norm();
            m.dsucopy(b);
            k = ctx.BIG.BIGBITS * n;

            while (FF.comp(x, m) >= 0) {
                x.sub(m);
                x.norm();
            }

            while (k > 0) {
                m.shr();

                if (FF.comp(x, m) >= 0) {
                    x.sub(m);
                    x.norm();
                }

                k--;
            }

            r.copy(x);
            r.mod(b);

            return r;
        },

        /* Set return=1/this mod p. Binary method - a<p on entry */
        invmodp: function(p) {
            var n = p.length,
                u = new FF(n),
                v = new FF(n),
                x1 = new FF(n),
                x2 = new FF(n),
                t = new FF(n),
                one = new FF(n);

            one.one();
            u.copy(this);
            v.copy(p);
            x1.copy(one);
            x2.zero();

            // reduce n in here as well!
            while (FF.comp(u, one) !== 0 && FF.comp(v, one) !== 0) {
                while (u.parity() === 0) {
                    u.shr();
                    if (x1.parity() !== 0) {
                        x1.add(p);
                        x1.norm();
                    }
                    x1.shr();
                }

                while (v.parity() === 0) {
                    v.shr();
                    if (x2.parity() !== 0) {
                        x2.add(p);
                        x2.norm();
                    }
                    x2.shr();
                }

                if (FF.comp(u, v) >= 0) {
                    u.sub(v);
                    u.norm();

                    if (FF.comp(x1, x2) >= 0) {
                        x1.sub(x2);
                    } else {
                        t.copy(p);
                        t.sub(x2);
                        x1.add(t);
                    }

                    x1.norm();
                } else {
                    v.sub(u);
                    v.norm();

                    if (FF.comp(x2, x1) >= 0) {
                        x2.sub(x1);
                    } else {
                        t.copy(p);
                        t.sub(x1);
                        x2.add(t);
                    }

                    x2.norm();
                }
            }

            if (FF.comp(u, one) === 0) {
                this.copy(x1);
            } else {
                this.copy(x2);
            }
        },

        /* nresidue mod m */
        nres: function(m) {
            var n = m.length,
                d;

            if (n === 1) {
                d = new ctx.DBIG(0);
                d.hcopy(this.v[0]);
                d.shl(ctx.BIG.NLEN * ctx.BIG.BASEBITS);
                this.v[0].copy(d.mod(m.v[0]));
            } else {
                d = new FF(2 * n);
                d.dsucopy(this);
                this.copy(d.dmod(m));
            }
        },

        redc: function(m, ND) {
            var n = m.length,
                d;

            if (n === 1) {
                d = new ctx.DBIG(0);
                d.hcopy(this.v[0]);
                this.v[0].copy(ctx.BIG.monty(m.v[0], (1 << ctx.BIG.BASEBITS) - ND.v[0].w[0], d));
            } else {
                d = new FF(2 * n);
                this.mod(m);
                d.dscopy(this);
                this.copy(d.reduce(m, ND));
                this.mod(m);
            }
        },

        mod2m: function(m) {
            for (var i = m; i < this.length; i++) {
                this.v[i].zero();
            }
        },

        /* U=1/a mod 2^m - Arazi & Qi */
        invmod2m: function() {
            var n = this.length,
                b = new FF(n),
                c = new FF(n),
                U = new FF(n),
                t, i;

            U.zero();
            U.v[0].copy(this.v[0]);
            U.v[0].invmod2m();

            for (i = 1; i < n; i <<= 1) {
                b.copy(this);
                b.mod2m(i);
                t = FF.mul(U, b);
                t.shrw(i);
                b.copy(t);
                c.copy(this);
                c.shrw(i);
                c.mod2m(i);
                c.lmul(U);
                c.mod2m(i);

                b.add(c);
                b.norm();
                b.lmul(U);
                b.mod2m(i);

                c.one();
                c.shlw(i);
                b.revsub(c);
                b.norm();
                b.shlw(i);
                U.add(b);
            }
            U.norm();

            return U;
        },

        random: function(rng) {
            var n = this.length,
                i;

            for (i = 0; i < n; i++) {
                this.v[i].copy(ctx.BIG.random(rng));
            }

            /* make sure top bit is 1 */
            while (this.v[n - 1].nbits() < ctx.BIG.MODBYTES * 8) {
                this.v[n - 1].copy(ctx.BIG.random(rng));
            }
        },

        /* generate random x */
        randomnum: function(p, rng) {
            var n = this.length,
                d = new FF(2 * n),
                i;

            for (i = 0; i < 2 * n; i++) {
                d.v[i].copy(ctx.BIG.random(rng));
            }

            this.copy(d.dmod(p));
        },

        /* this*=y mod p */
        modmul: function(y, p, nd) {
            var ex = this.P_EXCESS(),
                ey = y.P_EXCESS(),
                n = p.length,
                d;

            if ((ex + 1) >= Math.floor((FF.P_FEXCESS - 1) / (ey + 1))) {
                this.mod(p);
            }

            if (n === 1) {
                d = ctx.BIG.mul(this.v[0], y.v[0]);
                this.v[0].copy(ctx.BIG.monty(p.v[0], (1 << ctx.BIG.BASEBITS) - nd.v[0].w[0], d));
            } else {
                d = FF.mul(this, y);
                this.copy(d.reduce(p, nd));
            }
        },

        /* this*=y mod p */
        modsqr: function(p, nd) {
            var ex = this.P_EXCESS(),
                n, d;

            if ((ex + 1) >= Math.floor((FF.P_FEXCESS - 1) / (ex + 1))) {
                this.mod(p);
            }
            n = p.length;

            if (n === 1) {
                d = ctx.BIG.sqr(this.v[0]);
                this.v[0].copy(ctx.BIG.monty(p.v[0], (1 << ctx.BIG.BASEBITS) - nd.v[0].w[0], d));
            } else {
                d = FF.sqr(this);
                this.copy(d.reduce(p, nd));
            }
        },

        /* this=this^e mod p using side-channel resistant Montgomery Ladder, for large e */
        skpow: function(e, p) {
            var n = p.length,
                R0 = new FF(n),
                R1 = new FF(n),
                ND = p.invmod2m(),
                i, b;

            this.mod(p);
            R0.one();
            R1.copy(this);
            R0.nres(p);
            R1.nres(p);

            for (i = 8 * ctx.BIG.MODBYTES * n - 1; i >= 0; i--) {
                b = e.v[Math.floor(i / ctx.BIG.BIGBITS)].bit(i % ctx.BIG.BIGBITS);

                this.copy(R0);
                this.modmul(R1, p, ND);

                FF.cswap(R0, R1, b);
                R0.modsqr(p, ND);

                R1.copy(this);
                FF.cswap(R0, R1, b);
            }

            this.copy(R0);
            this.redc(p, ND);
        },

        /* this =this^e mod p using side-channel resistant Montgomery Ladder, for short e */
        skspow: function(e, p) {
            var n = p.length,
                R0 = new FF(n),
                R1 = new FF(n),
                ND = p.invmod2m(),
                i, b;

            this.mod(p);
            R0.one();
            R1.copy(this);
            R0.nres(p);
            R1.nres(p);

            for (i = 8 * ctx.BIG.MODBYTES - 1; i >= 0; i--) {
                b = e.bit(i);
                this.copy(R0);
                this.modmul(R1, p, ND);

                FF.cswap(R0, R1, b);
                R0.modsqr(p, ND);

                R1.copy(this);
                FF.cswap(R0, R1, b);
            }
            this.copy(R0);
            this.redc(p, ND);
        },

        /* raise to an integer power - right-to-left method */
        power: function(e, p) {
            var n = p.length,
                f = true,
                w = new FF(n),
                ND = p.invmod2m();

            w.copy(this);
            w.nres(p);

            if (e == 2) {
                this.copy(w);
                this.modsqr(p, ND);
            } else {
                for (;;) {
                    if (e % 2 == 1) {
                        if (f) {
                            this.copy(w);
                        } else {
                            this.modmul(w, p, ND);
                        }
                        f = false;
                    }
                    e >>= 1;
                    if (e === 0) {
                        break;
                    }
                    w.modsqr(p, ND);
                }
            }

            this.redc(p, ND);
        },

        /* this=this^e mod p, faster but not side channel resistant */
        pow: function(e, p) {
            var n = p.length,
                w = new FF(n),
                ND = p.invmod2m(),
                i, b;

            w.copy(this);
            this.one();
            this.nres(p);
            w.nres(p);

            for (i = 8 * ctx.BIG.MODBYTES * n - 1; i >= 0; i--) {
                this.modsqr(p, ND);
                b = e.v[Math.floor(i / ctx.BIG.BIGBITS)].bit(i % ctx.BIG.BIGBITS);
                if (b === 1) {
                    this.modmul(w, p, ND);
                }
            }

            this.redc(p, ND);
        },

        /* double exponentiation r=x^e.y^f mod p */
        pow2: function(e, y, f, p) {
            var n = p.length,
                xn = new FF(n),
                yn = new FF(n),
                xy = new FF(n),
                ND = p.invmod2m(),
                i, eb, fb;

            xn.copy(this);
            yn.copy(y);
            xn.nres(p);
            yn.nres(p);
            xy.copy(xn);
            xy.modmul(yn, p, ND);
            this.one();
            this.nres(p);

            for (i = 8 * ctx.BIG.MODBYTES - 1; i >= 0; i--) {
                eb = e.bit(i);
                fb = f.bit(i);
                this.modsqr(p, ND);

                if (eb == 1) {
                    if (fb == 1) {
                        this.modmul(xy, p, ND);
                    } else {
                        this.modmul(xn, p, ND);
                    }
                } else {
                    if (fb == 1) {
                        this.modmul(yn, p, ND);
                    }
                }
            }
            this.redc(p, ND);
        },

        /* quick and dirty check for common factor with n */
        cfactor: function(s) {
            var n = this.length,
                x = new FF(n),
                y = new FF(n),
                r, g;

            y.set(s);

            x.copy(this);
            x.norm();

            do {
                x.sub(y);
                x.norm();
                while (!x.iszilch() && x.parity() === 0) {
                    x.shr();
                }
            } while (FF.comp(x, y) > 0);

            g = x.v[0].get(0);
            r = FF.igcd(s, g);
            if (r > 1) {
                return true;
            }

            return false;
        }
    };

    /* compare x and y - must be normalised, and of same length */
    FF.comp = function(a, b) {
        var i, j;

        for (i = a.length - 1; i >= 0; i--) {
            j = ctx.BIG.comp(a.v[i], b.v[i]);
            if (j !== 0) {
                return j;
            }
        }

        return 0;
    };

    FF.fromBytes = function(x, b) {
        var i;

        for (i = 0; i < x.length; i++) {
            x.v[i] = ctx.BIG.frombytearray(b, (x.length - i - 1) * ctx.BIG.MODBYTES);
        }
    };

    /* in-place swapping using xor - side channel resistant - lengths must be the same */
    FF.cswap = function(a, b, d) {
        var i;

        for (i = 0; i < a.length; i++) {
            //  ctx.BIG.cswap(a.v[i],b.v[i],d);
            a.v[i].cswap(b.v[i], d);
        }
    };

    /* z=x*y. Assumes x and y are of same length. */
    FF.mul = function(x, y) {
        var n = x.length,
            z = new FF(2 * n),
            t = new FF(2 * n);

        z.karmul(0, x, 0, y, 0, t, 0, n);

        return z;
    };

    /* z=x^2 */
    FF.sqr = function(x) {
        var n = x.length,
            z = new FF(2 * n),
            t = new FF(2 * n);

        z.karsqr(0, x, 0, t, 0, n);

        return z;
    };

    FF.igcd = function(x, y) { /* integer GCD, returns GCD of x and y */
        var r;

        if (y === 0) {
            return x;
        }

        while ((r = x % y) !== 0) {
            x = y;
            y = r;
        }

        return y;
    };

    /* Miller-Rabin test for primality. Slow. */
    FF.prime = function(p, rng) {
        var n = p.length,
            s = 0,
            loop,
            d = new FF(n),
            x = new FF(n),
            unity = new FF(n),
            nm1 = new FF(n),
            sf = 4849845, /* 3*5*.. *19 */
            i, j;

        p.norm();

        if (p.cfactor(sf)) {
            return false;
        }

        unity.one();
        nm1.copy(p);
        nm1.sub(unity);
        nm1.norm();
        d.copy(nm1);

        while (d.parity() === 0) {
            d.shr();
            s++;
        }

        if (s === 0) {
            return false;
        }

        for (i = 0; i < 10; i++) {
            x.randomnum(p, rng);
            x.pow(d, p);

            if (FF.comp(x, unity) === 0 || FF.comp(x, nm1) === 0) {
                continue;
            }

            loop = false;

            for (j = 1; j < s; j++) {
                x.power(2, p);

                if (FF.comp(x, unity) === 0) {
                    return false;
                }

                if (FF.comp(x, nm1) === 0) {
                    loop = true;
                    break;
                }
            }
            if (loop) {
                continue;
            }

            return false;
        }

        return true;
    };

    return FF;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports.FF = FF;
}

},{}],"./fp12":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* AMCL Fp^12 functions */

/* FP12 elements are of the form a+i.b+i^2.c */

var FP12 = function(ctx) {
    "use strict";

    /* general purpose constructor */
    var FP12 = function(d, e, f) {
        if (d instanceof FP12) {
            this.a = new ctx.FP4(d.a);
            this.b = new ctx.FP4(d.b);
            this.c = new ctx.FP4(d.c);
        } else {
            this.a = new ctx.FP4(d);
            this.b = new ctx.FP4(e);
            this.c = new ctx.FP4(f);
        }
    };

    FP12.prototype = {
        /* reduce all components of this mod Modulus */
        reduce: function() {
            this.a.reduce();
            this.b.reduce();
            this.c.reduce();
        },

        /* normalize all components of this mod Modulus */
        norm: function() {
            this.a.norm();
            this.b.norm();
            this.c.norm();
        },

        /* test x==0 ? */
        iszilch: function() {
            this.reduce();
            return (this.a.iszilch() && this.b.iszilch() && this.c.iszilch());
        },

        /* test x==1 ? */
        isunity: function() {
            var one = new ctx.FP4(1);
            return (this.a.equals(one) && this.b.iszilch() && this.b.iszilch());
        },

        /* extract a from this */
        geta: function() {
            return this.a;
        },

        /* extract b */
        getb: function() {
            return this.b;
        },

        /* extract c */
        getc: function() {
            return this.c;
        },

        /* return 1 if x==y, else 0 */
        equals: function(x) {
            return (this.a.equals(x.a) && this.b.equals(x.b) && this.c.equals(x.c));
        },

        /* copy this=x */
        copy: function(x) {
            this.a.copy(x.a);
            this.b.copy(x.b);
            this.c.copy(x.c);
        },

        /* set this=1 */
        one: function() {
            this.a.one();
            this.b.zero();
            this.c.zero();
        },

        /* this=conj(this) */
        conj: function() {
            this.a.conj();
            this.b.nconj();
            this.c.conj();
        },

        /* set this from 3 FP4s */
        set: function(d, e, f) {
            this.a.copy(d);
            this.b.copy(e);
            this.c.copy(f);
        },

        /* set this from one ctx.FP4 */
        seta: function(d) {
            this.a.copy(d);
            this.b.zero();
            this.c.zero();
        },

        /* Granger-Scott Unitary Squaring */
        usqr: function() {
            var A = new ctx.FP4(this.a), //A.copy(this.a)
                B = new ctx.FP4(this.c), //B.copy(this.c)
                C = new ctx.FP4(this.b), //C.copy(this.b)
                D = new ctx.FP4(0);

            this.a.sqr();
            D.copy(this.a);
            D.add(this.a);
            this.a.add(D);

            A.nconj();

            A.add(A);
            this.a.add(A);
            B.sqr();
            B.times_i();

            D.copy(B);
            D.add(B);
            B.add(D);

            C.sqr();
            D.copy(C);
            D.add(C);
            C.add(D);

            this.b.conj();
            this.b.add(this.b);
            this.c.nconj();

            this.c.add(this.c);
            this.b.add(B);
            this.c.add(C);
            this.reduce();
        },

        /* Chung-Hasan SQR2 method from http://cacr.uwaterloo.ca/techreports/2006/cacr2006-24.pdf */
        sqr: function() {
            var A = new ctx.FP4(this.a), //A.copy(this.a)
                B = new ctx.FP4(this.b), //B.copy(this.b)
                C = new ctx.FP4(this.c), //C.copy(this.c)
                D = new ctx.FP4(this.a); //D.copy(this.a)

            A.sqr();
            B.mul(this.c);
            B.add(B); //B.norm();
            C.sqr();
            D.mul(this.b);
            D.add(D);

            this.c.add(this.a);
            this.c.add(this.b);
            this.c.norm();
            this.c.sqr();

            this.a.copy(A);

            A.add(B);
            A.add(C);
            A.add(D);
            A.neg();
            B.times_i();
            C.times_i();

            this.a.add(B);
            this.b.copy(C);
            this.b.add(D);
            this.c.add(A);

            this.norm();
        },

        /* FP12 full multiplication this=this*y */
        mul: function(y) {
            var z0 = new ctx.FP4(this.a), //z0.copy(this.a)
                z1 = new ctx.FP4(0),
                z2 = new ctx.FP4(this.b), //z2.copy(this.b)
                z3 = new ctx.FP4(0),
                t0 = new ctx.FP4(this.a), //t0.copy(this.a)
                t1 = new ctx.FP4(y.a); //t1.copy(y.a)

            z0.mul(y.a);
            z2.mul(y.b);

            t0.add(this.b);
            t1.add(y.b);

            t0.norm();
            t1.norm();

            z1.copy(t0);
            z1.mul(t1);
            t0.copy(this.b);
            t0.add(this.c);

            t1.copy(y.b);
            t1.add(y.c);

            t0.norm();
            t1.norm();
            z3.copy(t0);
            z3.mul(t1);

            t0.copy(z0);
            t0.neg();
            t1.copy(z2);
            t1.neg();

            z1.add(t0);
            this.b.copy(z1);
            this.b.add(t1);

            z3.add(t1);
            z2.add(t0);

            t0.copy(this.a);
            t0.add(this.c);
            t1.copy(y.a);
            t1.add(y.c);

            t0.norm();
            t1.norm();

            t0.mul(t1);
            z2.add(t0);

            t0.copy(this.c);
            t0.mul(y.c);
            t1.copy(t0);
            t1.neg();

            this.c.copy(z2);
            this.c.add(t1);
            z3.add(t1);
            t0.times_i();
            this.b.add(t0);
            // z3.norm();
            z3.times_i();
            this.a.copy(z0);
            this.a.add(z3);

            this.norm();
        },

        /* Special case this*=y that arises from special form of ATE pairing line function */
        smul: function(y, twist) {
            if (twist == ctx.ECP.D_TYPE) {
                var z0 = new ctx.FP4(this.a), //z0.copy(this.a);
                    z2 = new ctx.FP4(this.b), //z2.copy(this.b);
                    z3 = new ctx.FP4(this.b), //z3.copy(this.b);
                    t0 = new ctx.FP4(0),
                    t1 = new ctx.FP4(y.a); //t1.copy(y.a);

                z0.mul(y.a);
                z2.pmul(y.b.real());
                this.b.add(this.a);
                t1.real().add(y.b.real());

                this.b.norm();
                t1.norm();

                this.b.mul(t1);
                z3.add(this.c);
                z3.norm();
                z3.pmul(y.b.real());

                t0.copy(z0);
                t0.neg();
                t1.copy(z2);
                t1.neg();

                this.b.add(t0);

                this.b.add(t1);
                z3.add(t1);
                z2.add(t0);

                t0.copy(this.a);
                t0.add(this.c);
                t0.norm();
                t0.mul(y.a);
                this.c.copy(z2);
                this.c.add(t0);

                z3.times_i();
                this.a.copy(z0);
                this.a.add(z3);
            }

            if (twist == ctx.ECP.M_TYPE) {
                var z0=new ctx.FP4(this.a);
                var z1=new ctx.FP4(0);
                var z2=new ctx.FP4(0);
                var z3=new ctx.FP4(0);
                var t0=new ctx.FP4(this.a);
                var t1=new ctx.FP4(0);

                z0.mul(y.a);
                t0.add(this.b);
                t0.norm();

                z1.copy(t0); z1.mul(y.a);
                t0.copy(this.b); t0.add(this.c);
                t0.norm();

                z3.copy(t0); //z3.mul(y.c);
                z3.pmul(y.c.getb());
                z3.times_i();

                t0.copy(z0); t0.neg();

                z1.add(t0);
                this.b.copy(z1);
                z2.copy(t0);

                t0.copy(this.a); t0.add(this.c);
                t1.copy(y.a); t1.add(y.c);

                t0.norm();
                t1.norm();

                t0.mul(t1);
                z2.add(t0);

                t0.copy(this.c);

                t0.pmul(y.c.getb());
                t0.times_i();

                t1.copy(t0); t1.neg();

                this.c.copy(z2); this.c.add(t1);
                z3.add(t1);
                t0.times_i();
                this.b.add(t0);
                z3.norm();
                z3.times_i();
                this.a.copy(z0); this.a.add(z3);
            }

            this.norm();
        },

        /* this=1/this */
        inverse: function() {
            var f0 = new ctx.FP4(this.a), //f0.copy(this.a)
                f1 = new ctx.FP4(this.b), //f1.copy(this.b)
                f2 = new ctx.FP4(this.a), //f2.copy(this.a)
                f3 = new ctx.FP4(0);

            f0.sqr();
            f1.mul(this.c);
            f1.times_i();
            f0.sub(f1);
            f0.norm();

            f1.copy(this.c);
            f1.sqr();
            f1.times_i();
            f2.mul(this.b);
            f1.sub(f2);
            f1.norm();

            f2.copy(this.b);
            f2.sqr();
            f3.copy(this.a);
            f3.mul(this.c);
            f2.sub(f3);
            f2.norm();

            f3.copy(this.b);
            f3.mul(f2);
            f3.times_i();
            this.a.mul(f0);
            f3.add(this.a);
            this.c.mul(f1);
            this.c.times_i();

            f3.add(this.c);
            f3.norm();
            f3.inverse();
            this.a.copy(f0);
            this.a.mul(f3);
            this.b.copy(f1);
            this.b.mul(f3);
            this.c.copy(f2);
            this.c.mul(f3);
        },

        /* this=this^p, where p=Modulus, using Frobenius */
        frob: function(f) {
            var f2 = new ctx.FP2(f),
                f3 = new ctx.FP2(f);

            f2.sqr();
            f3.mul(f2);

            this.a.frob(f3);
            this.b.frob(f3);
            this.c.frob(f3);

            this.b.pmul(f);
            this.c.pmul(f2);
        },

        /* trace function */
        trace: function() {
            var t = new ctx.FP4(0);

            t.copy(this.a);
            t.imul(3);
            t.reduce();

            return t;
        },

        /* convert this to hex string */
        toString: function() {
            return ("[" + this.a.toString() + "," + this.b.toString() + "," + this.c.toString() + "]");
        },

        /* convert this to byte array */
        toBytes: function(w) {
            var t = [],
                i;

            this.a.geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i] = t[i];
            }
            this.a.geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + ctx.BIG.MODBYTES] = t[i];
            }
            this.a.getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 2 * ctx.BIG.MODBYTES] = t[i];
            }
            this.a.getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 3 * ctx.BIG.MODBYTES] = t[i];
            }

            this.b.geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 4 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 5 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 6 * ctx.BIG.MODBYTES] = t[i];
            }
            this.b.getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 7 * ctx.BIG.MODBYTES] = t[i];
            }

            this.c.geta().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 8 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.geta().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 9 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.getb().getA().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 10 * ctx.BIG.MODBYTES] = t[i];
            }
            this.c.getb().getB().toBytes(t);
            for (i = 0; i < ctx.BIG.MODBYTES; i++) {
                w[i + 11 * ctx.BIG.MODBYTES] = t[i];
            }
        },

        /* set this=this^e */
        pow: function(e) {
            var e3, w, nb, i, bt;

            this.norm();
            e.norm();

            e3 = new ctx.BIG(e);
            e3.pmul(3);
            e3.norm();

            w = new FP12(this); //w.copy(this);
            nb = e3.nbits();

            for (i = nb - 2; i >= 1; i--)
            {
                w.usqr();
                bt = e3.bit(i) - e.bit(i);

                if (bt == 1) {
                    w.mul(this);
                }
                if (bt == -1) {
                    this.conj();
                    w.mul(this);
                    this.conj();
                }
            }
            w.reduce();

            return w;
        },

        /* constant time powering by small integer of max length bts */
        pinpow: function(e, bts) {
            var R = [],
                i, b;

            R[0] = new FP12(1);
            R[1] = new FP12(this);

            for (i = bts - 1; i >= 0; i--) {
                b = (e >> i) & 1;
                R[1 - b].mul(R[b]);
                R[b].usqr();
            }

            this.copy(R[0]);
        },

        /* Faster compressed powering for unitary elements */
        compow: function(e, r) {
            var fa, fb, f, q, m, a, b, g1, g2, c, cp, cpm1, cpm2;

            fa = new ctx.BIG(0);
            fa.rcopy(ctx.ROM_FIELD.Fra);
            fb = new ctx.BIG(0);
            fb.rcopy(ctx.ROM_FIELD.Frb);
            f = new ctx.FP2(fa, fb);

            q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_FIELD.Modulus);

            m = new ctx.BIG(q);
            m.mod(r);

            a = new ctx.BIG(e);
            a.mod(m);

            b = new ctx.BIG(e);
            b.div(m);

            g1 = new FP12(0);
            g2 = new FP12(0);
            g1.copy(this);

            c = g1.trace();

            if (b.iszilch()) {
                c=c.xtr_pow(e);
                return c;
            }

            g2.copy(g1);
            g2.frob(f);
            cp = g2.trace();
            g1.conj();
            g2.mul(g1);
            cpm1 = g2.trace();
            g2.mul(g1);
            cpm2 = g2.trace();

            c = c.xtr_pow2(cp, cpm1, cpm2, a, b);
            return c;
        }
    };

    /* convert from byte array to FP12 */
    FP12.fromBytes = function(w) {
        var t = [],
            i, a, b, c, d, e, f, g, r;

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b); //c.bset(a,b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 2 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 3 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b); //d.bset(a,b);

        e = new ctx.FP4(c, d); //e.set(c,d);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 4 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 5 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b); //c.bset(a,b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 6 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 7 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b);

        f = new ctx.FP4(c, d); //f.set(c,d);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 8 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 9 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        c = new ctx.FP2(a, b); //c.bset(a,b);

        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 10 * ctx.BIG.MODBYTES];
        }
        a = ctx.BIG.fromBytes(t);
        for (i = 0; i < ctx.BIG.MODBYTES; i++) {
            t[i] = w[i + 11 * ctx.BIG.MODBYTES];
        }
        b = ctx.BIG.fromBytes(t);
        d = new ctx.FP2(a, b); //d.bset(a,b);

        g = new ctx.FP4(c, d); //g.set(c,d);

        r = new FP12(e, f, g); //r.set(e,f,g);

        return r;
    };

    /* p=q0^u0.q1^u1.q2^u2.q3^u3 */
    /* Timing attack secure, but not cache attack secure */

    FP12.pow4 = function(q, u) {
        var a = [],
            g = [],
            s = [],
            c = new FP12(1),
            p = new FP12(0),
            t = [],
            mt = new ctx.BIG(0),
            w = [],
            i, j, nb, m;

        for (i = 0; i < 4; i++) {
            t[i] = new ctx.BIG(u[i]);
        }

        s[0] = new FP12(0);
        s[1] = new FP12(0);

        g[0] = new FP12(q[0]);
        s[0].copy(q[1]);
        s[0].conj();
        g[0].mul(s[0]);
        g[1] = new FP12(g[0]);
        g[2] = new FP12(g[0]);
        g[3] = new FP12(g[0]);
        g[4] = new FP12(q[0]);
        g[4].mul(q[1]);
        g[5] = new FP12(g[4]);
        g[6] = new FP12(g[4]);
        g[7] = new FP12(g[4]);

        s[1].copy(q[2]);
        s[0].copy(q[3]);
        s[0].conj();
        s[1].mul(s[0]);
        s[0].copy(s[1]);
        s[0].conj();
        g[1].mul(s[0]);
        g[2].mul(s[1]);
        g[5].mul(s[0]);
        g[6].mul(s[1]);
        s[1].copy(q[2]);
        s[1].mul(q[3]);
        s[0].copy(s[1]);
        s[0].conj();
        g[0].mul(s[0]);
        g[3].mul(s[1]);
        g[4].mul(s[0]);
        g[7].mul(s[1]);

        /* if power is even add 1 to power, and add q to correction */

        for (i = 0; i < 4; i++) {
            if (t[i].parity() == 0) {
                t[i].inc(1);
                t[i].norm();
                c.mul(q[i]);
            }
            mt.add(t[i]);
            mt.norm();
        }
        c.conj();
        nb = 1 + mt.nbits();

        /* convert exponent to signed 1-bit window */
        for (j = 0; j < nb; j++) {
            for (i = 0; i < 4; i++) {
                a[i] = (t[i].lastbits(2) - 2);
                t[i].dec(a[i]);
                t[i].norm();
                t[i].fshr(1);
            }
            w[j] = (8 * a[0] + 4 * a[1] + 2 * a[2] + a[3]);
        }
        w[nb] = (8 * t[0].lastbits(2) + 4 * t[1].lastbits(2) + 2 * t[2].lastbits(2) + t[3].lastbits(2));
        p.copy(g[Math.floor((w[nb] - 1) / 2)]);

        for (i = nb - 1; i >= 0; i--) {
            m = w[i] >> 31;
            j = (w[i] ^ m) - m; /* j=abs(w[i]) */
            j = (j - 1) / 2;
            s[0].copy(g[j]);
            s[1].copy(g[j]);
            s[1].conj();
            p.usqr();
            p.mul(s[m & 1]);
        }
        p.mul(c); /* apply correction */
        p.reduce();

        return p;
    };

    return FP12;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports.FP12 = FP12;
}

},{}],"./fp2":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* Finite Field arithmetic  Fp^2 functions */

/* FP2 elements are of the form a+ib, where i is sqrt(-1) */

var FP2 = function(ctx) {
    "use strict";

    /* general purpose constructor */
    var FP2 = function(c, d) {
        if (c instanceof FP2) {
            this.a = new ctx.FP(c.a);
            this.b = new ctx.FP(c.b);
        } else {
            this.a = new ctx.FP(c);
            this.b = new ctx.FP(d);
        }
    };

    FP2.prototype = {
        /* reduce components mod Modulus */
        reduce: function() {
            this.a.reduce();
            this.b.reduce();
        },

        /* normalise components of w */
        norm: function() {
            this.a.norm();
            this.b.norm();
        },

        /* test this=0 ? */
        iszilch: function() {
            this.reduce();
            return (this.a.iszilch() && this.b.iszilch());
        },

        /* test this=1 ? */
        isunity: function() {
            var one = new ctx.FP(1);
            return (this.a.equals(one) && this.b.iszilch());
        },

        /* conditional copy of g to this depending on d */
        cmove: function(g, d) {
            this.a.cmove(g.a, d);
            this.b.cmove(g.b, d);
        },

        /* test this=x */
        equals: function(x) {
            return (this.a.equals(x.a) && this.b.equals(x.b));
        },

        /* extract a */
        getA: function() {
            return this.a.redc();
        },

        /* extract b */
        getB: function() {
            return this.b.redc();
        },

        /* set from pair of FPs */
        set: function(c, d) {
            this.a.copy(c);
            this.b.copy(d);
        },

        /* set a */
        seta: function(c) {
            this.a.copy(c);
            this.b.zero();
        },

        /* set from two BIGs */
        bset: function(c, d) {
            this.a.bcopy(c);
            this.b.bcopy(d);
        },

        /* set from one ctx.BIG */
        bseta: function(c) {
            this.a.bcopy(c);
            this.b.zero();
        },

        /* copy this=x */
        copy: function(x) {
            this.a.copy(x.a);
            this.b.copy(x.b);
        },

        /* set this=0 */
        zero: function() {
            this.a.zero();
            this.b.zero();
        },

        /* set this=1 */
        one: function() {
            this.a.one();
            this.b.zero();
        },

        /* negate this */
        neg: function() {
            //      this.norm();
            var m = new ctx.FP(this.a),
                t = new ctx.FP(0);

            m.add(this.b);
            m.neg();
            //      m.norm();
            t.copy(m);
            t.add(this.b);
            this.b.copy(m);
            this.b.add(this.a);
            this.a.copy(t);
            //this.norm();
        },

        /* conjugate this */
        conj: function() {
            this.b.neg();
            this.b.norm();
        },

        /* this+=a */
        add: function(x) {
            this.a.add(x.a);
            this.b.add(x.b);
        },

        /* this-=x */
        sub: function(x) {
            var m = new FP2(x); //var m=new FP2(0); m.copy(x);
            m.neg();
            this.add(m);
        },

        rsub: function(x) {
            this.neg();
            this.add(x);
        },

        /* this*=s, where s is FP */
        pmul: function(s) {
            this.a.mul(s);
            this.b.mul(s);
        },

        /* this*=c, where s is int */
        imul: function(c) {
            this.a.imul(c);
            this.b.imul(c);
        },

        /* this*=this */
        sqr: function() {
            //      this.norm();

            var w1 = new ctx.FP(this.a),
                w3 = new ctx.FP(this.a),
                mb = new ctx.FP(this.b);

            //      w3.mul(this.b);
            w1.add(this.b);


            w3.add(this.a);
            w3.norm();
            this.b.mul(w3);

            mb.neg();
            this.a.add(mb);

            this.a.norm();
            w1.norm();

            this.a.mul(w1);
            //      this.b.copy(w3); this.b.add(w3);
            //      this.b.norm();
        },

        /* this*=y */
        /* Now using Lazy reduction - inputs must be normed */
        mul: function(y) {
            var p = new ctx.BIG(0),
                pR = new ctx.DBIG(0),
                A, B, C, D, E, F;

            p.rcopy(ctx.ROM_FIELD.Modulus);
            pR.ucopy(p);

            if ((this.a.XES + this.b.XES) * (y.a.XES + y.b.XES) > ctx.FP.FEXCESS) {
                if (this.a.XES > 1) {
                    this.a.reduce();
                }

                if (this.b.XES > 1) {
                    this.b.reduce();
                }
            }

            A = ctx.BIG.mul(this.a.f, y.a.f);
            B = ctx.BIG.mul(this.b.f, y.b.f);

            C = new ctx.BIG(this.a.f);
            D = new ctx.BIG(y.a.f);

            C.add(this.b.f);
            C.norm();
            D.add(y.b.f);
            D.norm();

            E = ctx.BIG.mul(C, D);
            F = new ctx.DBIG(0);
            F.copy(A);
            F.add(B);
            B.rsub(pR);

            A.add(B);
            A.norm();
            E.sub(F);
            E.norm();

            this.a.f.copy(ctx.FP.mod(A));
            this.a.XES = 3;
            this.b.f.copy(ctx.FP.mod(E));
            this.b.XES = 2;
        },

        /* sqrt(a+ib) = sqrt(a+sqrt(a*a-n*b*b)/2)+ib/(2*sqrt(a+sqrt(a*a-n*b*b)/2)) */
        /* returns true if this is QR */
        sqrt: function() {
            var w1, w2;

            if (this.iszilch()) {
                return true;
            }

            w1 = new ctx.FP(this.b);
            w2 = new ctx.FP(this.a);

            w1.sqr();
            w2.sqr();
            w1.add(w2);
            if (w1.jacobi() != 1) {
                this.zero();
                return false;
            }
            w1 = w1.sqrt();
            w2.copy(this.a);
            w2.add(w1);
            w2.norm();
            w2.div2();
            if (w2.jacobi() != 1) {
                w2.copy(this.a);
                w2.sub(w1);
                w2.norm();
                w2.div2();
                if (w2.jacobi() != 1) {
                    this.zero();
                    return false;
                }
            }
            w2 = w2.sqrt();
            this.a.copy(w2);
            w2.add(w2);
            w2.inverse();
            this.b.mul(w2);

            return true;
        },

        /* convert this to hex string */
        toString: function() {
            return ("[" + this.a.toString() + "," + this.b.toString() + "]");
        },

        /* this=1/this */
        inverse: function() {
            var w1, w2;

            this.norm();

            w1 = new ctx.FP(this.a);
            w2 = new ctx.FP(this.b);

            w1.sqr();
            w2.sqr();
            w1.add(w2);
            w1.inverse();
            this.a.mul(w1);
            w1.neg();
            w1.norm();
            this.b.mul(w1);
        },

        /* this/=2 */
        div2: function() {
            this.a.div2();
            this.b.div2();
        },

        /* this*=sqrt(-1) */
        times_i: function() {
            var z = new ctx.FP(this.a); //z.copy(this.a);
            this.a.copy(this.b);
            this.a.neg();
            this.b.copy(z);
        },

        /* w*=(1+sqrt(-1)) */
        /* where X*2-(1+sqrt(-1)) is irreducible for FP4, assumes p=3 mod 8 */
        mul_ip: function() {
            //      this.norm();
            var t = new FP2(this), // t.copy(this);
                z = new ctx.FP(this.a); //z.copy(this.a);

            this.a.copy(this.b);
            this.a.neg();
            this.b.copy(z);
            this.add(t);
            //      this.norm();
        },

        div_ip2: function() {
            var t = new FP2(0);
            t.a.copy(this.a);
            t.a.add(this.b);
            t.b.copy(this.b);
            t.b.sub(this.a);
            this.copy(t);
        },

        /* w/=(1+sqrt(-1)) */
        div_ip: function() {
            var t = new FP2(0);
            this.norm();
            t.a.copy(this.a);
            t.a.add(this.b);
            t.b.copy(this.b);
            t.b.sub(this.a);
            this.copy(t);
            this.norm();
            this.div2();
        },

        /* this=this^e */
        pow: function(e) {
            this.norm();

            var r = new FP2(1),
                x = new FP2(this), //x.copy(this);
                bt;

            e.norm();

            for (;;) {
                bt = e.parity();
                e.fshr(1);

                if (bt == 1) {
                    r.mul(x);
                }

                if (e.iszilch()) {
                    break;
                }
                x.sqr();
            }

            r.reduce();

            return r;
        }

    };

    return FP2;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports.FP2 = FP2;
}

},{}],"./fp4":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* Finite Field arithmetic  Fp^4 functions */

/* FP4 elements are of the form a+ib, where i is sqrt(-1+sqrt(-1))  */

var FP4 = function(ctx) {
    "use strict";

    /* general purpose constructor */
    var FP4 = function(c, d) {
        if (c instanceof FP4) {
            this.a = new ctx.FP2(c.a);
            this.b = new ctx.FP2(c.b);
        } else {
            this.a = new ctx.FP2(c);
            this.b = new ctx.FP2(d);
        }
    };

    FP4.prototype = {
        /* reduce all components of this mod Modulus */
        reduce: function() {
            this.a.reduce();
            this.b.reduce();
        },

        /* normalise all components of this mod Modulus */
        norm: function() {
            this.a.norm();
            this.b.norm();
        },

        /* test this==0 ? */
        iszilch: function() {
            this.reduce();
            return (this.a.iszilch() && this.b.iszilch());
        },

        /* test this==1 ? */
        isunity: function() {
            var one = new ctx.FP2(1);
            return (this.a.equals(one) && this.b.iszilch());
        },

        /* test is w real? That is in a+ib test b is zero */
        isreal: function() {
            return this.b.iszilch();
        },

        /* extract real part a */
        real: function() {
            return this.a;
        },

        geta: function() {
            return this.a;
        },

        /* extract imaginary part b */
        getb: function() {
            return this.b;
        },

        /* test this=x? */
        equals: function(x) {
            return (this.a.equals(x.a) && this.b.equals(x.b));
        },

        /* copy this=x */
        copy: function(x) {
            this.a.copy(x.a);
            this.b.copy(x.b);
        },

        /* this=0 */
        zero: function() {
            this.a.zero();
            this.b.zero();
        },

        /* this=1 */
        one: function() {
            this.a.one();
            this.b.zero();
        },

        /* set from two FP2s */
        set: function(c, d) {
            this.a.copy(c);
            this.b.copy(d);
        },

        /* set a */
        seta: function(c) {
            this.a.copy(c);
            this.b.zero();
        },

        /* this=-this */
        neg: function() {
            var m = new ctx.FP2(this.a), //m.copy(this.a);
                t = new ctx.FP2(0);

            m.add(this.b);
            m.neg();
            //  m.norm();
            t.copy(m);
            t.add(this.b);
            this.b.copy(m);
            this.b.add(this.a);
            this.a.copy(t);
            this.norm();
        },

        /* this=conjugate(this) */
        conj: function() {
            this.b.neg();
            this.norm();
        },

        /* this=-conjugate(this) */
        nconj: function() {
            this.a.neg();
            this.norm();
        },

        /* this+=x */
        add: function(x) {
            this.a.add(x.a);
            this.b.add(x.b);
        },

        /* this-=x */
        sub: function(x) {
            var m = new FP4(x); // m.copy(x);
            m.neg();
            this.add(m);
        },

        /* this*=s where s is FP2 */
        pmul: function(s) {
            this.a.mul(s);
            this.b.mul(s);
        },

        /* this*=c where s is int */
        imul: function(c) {
            this.a.imul(c);
            this.b.imul(c);
        },

        /* this*=this */
        sqr: function() {
            //      this.norm();

            var t1 = new ctx.FP2(this.a), //t1.copy(this.a)
                t2 = new ctx.FP2(this.b), //t2.copy(this.b)
                t3 = new ctx.FP2(this.a); //t3.copy(this.a)

            t3.mul(this.b);
            t1.add(this.b);
            t1.norm();
            t2.mul_ip();

            t2.add(this.a);
            t2.norm();
            this.a.copy(t1);

            this.a.mul(t2);

            t2.copy(t3);
            t2.mul_ip();
            t2.add(t3);
            //      t2.norm();  // ??

            t2.neg();

            this.a.add(t2);

            this.b.copy(t3);
            this.b.add(t3);

            this.norm();
        },

        /* this*=y */
        mul: function(y) {
            //      this.norm();

            var t1 = new ctx.FP2(this.a), //t1.copy(this.a)
                t2 = new ctx.FP2(this.b), //t2.copy(this.b)
                t3 = new ctx.FP2(0),
                t4 = new ctx.FP2(this.b); //t4.copy(this.b)

            t1.mul(y.a);
            t2.mul(y.b);
            t3.copy(y.b);
            t3.add(y.a);
            t4.add(this.a);

            t3.norm();
            t4.norm();

            t4.mul(t3);

            t3.copy(t1);
            t3.neg();
            t4.add(t3);
            //      t4.norm(); // ??

            // t4.sub(t1);

            t3.copy(t2);
            t3.neg();
            this.b.copy(t4);
            this.b.add(t3);

            t2.mul_ip();
            this.a.copy(t2);
            this.a.add(t1);

            this.norm();
        },

        /* convert to hex string */
        toString: function() {
            return ("[" + this.a.toString() + "," + this.b.toString() + "]");
        },

        /* this=1/this */
        inverse: function() {
            this.norm();

            var t1 = new ctx.FP2(this.a), //t1.copy(this.a);
                t2 = new ctx.FP2(this.b); // t2.copy(this.b);

            t1.sqr();
            t2.sqr();
            t2.mul_ip();
            t2.norm(); // ??
            t1.sub(t2);
            t1.inverse();
            this.a.mul(t1);
            t1.neg();
            t1.norm();
            this.b.mul(t1);
        },

        /* this*=i where i = sqrt(-1+sqrt(-1)) */
        times_i: function() {
            var s = new ctx.FP2(this.b), //s.copy(this.b);
                t = new ctx.FP2(this.b); //t.copy(this.b);

            s.times_i();
            t.add(s);
            this.b.copy(this.a);
            this.a.copy(t);
            this.norm();
        },

        /* this=this^q using Frobenius, where q is Modulus */
        frob: function(f) {
            this.a.conj();
            this.b.conj();
            this.b.mul(f);
        },

        /* this=this^e */
        pow: function(e) {
            this.norm();
            e.norm();

            var w = new FP4(this), //w.copy(this);
                z = new ctx.BIG(e), //z.copy(e);
                r = new FP4(1),
                bt;

            for (;;) {
                bt = z.parity();
                z.fshr(1);

                if (bt === 1) {
                    r.mul(w);
                }

                if (z.iszilch()) {
                    break;
                }

                w.sqr();
            }
            r.reduce();

            return r;
        },

        /* XTR xtr_a function */
        xtr_A: function(w, y, z) {
            var r = new FP4(w), //r.copy(w);
                t = new FP4(w); //t.copy(w);

            //y.norm(); // ??
            r.sub(y);
            r.norm();
            r.pmul(this.a);
            t.add(y);
            t.norm();
            t.pmul(this.b);
            t.times_i();

            this.copy(r);
            this.add(t);
            this.add(z);

            this.reduce();
        },

        /* XTR xtr_d function */
        xtr_D: function() {
            var w = new FP4(this); //w.copy(this);
            this.sqr();
            w.conj();
            w.add(w); //w.norm(); // ??
            this.sub(w);
            this.reduce();
        },

        /* r=x^n using XTR method on traces of FP12s */
        xtr_pow: function(n) {
            var a = new FP4(3),
                b = new FP4(this),
                c = new FP4(b),
                t = new FP4(0),
                r = new FP4(0),
                par, v, nb, i;

            c.xtr_D();

            n.norm();
            par = n.parity();
            v = new ctx.BIG(n);

            v.fshr(1);

            if (par === 0) {
                v.dec(1);
                v.norm();
            }

            nb = v.nbits();
            for (i = nb - 1; i >= 0; i--) {
                if (v.bit(i) != 1) {
                    t.copy(b);
                    this.conj();
                    c.conj();
                    b.xtr_A(a, this, c);
                    this.conj();
                    c.copy(t);
                    c.xtr_D();
                    a.xtr_D();
                } else {
                    t.copy(a);
                    t.conj();
                    a.copy(b);
                    a.xtr_D();
                    b.xtr_A(c, this, t);
                    c.xtr_D();
                }
            }

            if (par === 0) {
                r.copy(c);
            } else {
                r.copy(b);
            }
            r.reduce();

            return r;
        },

        /* r=ck^a.cl^n using XTR double exponentiation method on traces of FP12s. See Stam thesis. */
        xtr_pow2: function(ck, ckml, ckm2l, a, b) {
            a.norm();
            b.norm();

            var e = new ctx.BIG(a), //e.copy(a)
                d = new ctx.BIG(b), //d.copy(b)
                w = new ctx.BIG(0),
                cu = new FP4(ck), //cu.copy(ck), // can probably be passed in w/o copying
                cv = new FP4(this), //cv.copy(this),
                cumv = new FP4(ckml), //cumv.copy(ckml),
                cum2v = new FP4(ckm2l), //cum2v.copy(ckm2l),
                r = new FP4(0),
                t = new FP4(0),
                f2 = 0,
                i;

            while (d.parity() === 0 && e.parity() === 0) {
                d.fshr(1);
                e.fshr(1);
                f2++;
            }

            while (ctx.BIG.comp(d, e) !== 0) {
                if (ctx.BIG.comp(d, e) > 0) {
                    w.copy(e);
                    w.imul(4);
                    w.norm();

                    if (ctx.BIG.comp(d, w) <= 0) {
                        w.copy(d);
                        d.copy(e);
                        e.rsub(w);
                        e.norm();

                        t.copy(cv);
                        t.xtr_A(cu, cumv, cum2v);
                        cum2v.copy(cumv);
                        cum2v.conj();
                        cumv.copy(cv);
                        cv.copy(cu);
                        cu.copy(t);

                    } else if (d.parity() === 0) {
                        d.fshr(1);
                        r.copy(cum2v);
                        r.conj();
                        t.copy(cumv);
                        t.xtr_A(cu, cv, r);
                        cum2v.copy(cumv);
                        cum2v.xtr_D();
                        cumv.copy(t);
                        cu.xtr_D();
                    } else if (e.parity() == 1) {
                        d.sub(e);
                        d.norm();
                        d.fshr(1);
                        t.copy(cv);
                        t.xtr_A(cu, cumv, cum2v);
                        cu.xtr_D();
                        cum2v.copy(cv);
                        cum2v.xtr_D();
                        cum2v.conj();
                        cv.copy(t);
                    } else {
                        w.copy(d);
                        d.copy(e);
                        d.fshr(1);
                        e.copy(w);
                        t.copy(cumv);
                        t.xtr_D();
                        cumv.copy(cum2v);
                        cumv.conj();
                        cum2v.copy(t);
                        cum2v.conj();
                        t.copy(cv);
                        t.xtr_D();
                        cv.copy(cu);
                        cu.copy(t);
                    }
                }
                if (ctx.BIG.comp(d, e) < 0) {
                    w.copy(d);
                    w.imul(4);
                    w.norm();

                    if (ctx.BIG.comp(e, w) <= 0) {
                        e.sub(d);
                        e.norm();
                        t.copy(cv);
                        t.xtr_A(cu, cumv, cum2v);
                        cum2v.copy(cumv);
                        cumv.copy(cu);
                        cu.copy(t);
                    } else if (e.parity() === 0) {
                        w.copy(d);
                        d.copy(e);
                        d.fshr(1);
                        e.copy(w);
                        t.copy(cumv);
                        t.xtr_D();
                        cumv.copy(cum2v);
                        cumv.conj();
                        cum2v.copy(t);
                        cum2v.conj();
                        t.copy(cv);
                        t.xtr_D();
                        cv.copy(cu);
                        cu.copy(t);
                    } else if (d.parity() == 1) {
                        w.copy(e);
                        e.copy(d);
                        w.sub(d);
                        w.norm();
                        d.copy(w);
                        d.fshr(1);
                        t.copy(cv);
                        t.xtr_A(cu, cumv, cum2v);
                        cumv.conj();
                        cum2v.copy(cu);
                        cum2v.xtr_D();
                        cum2v.conj();
                        cu.copy(cv);
                        cu.xtr_D();
                        cv.copy(t);
                    } else {
                        d.fshr(1);
                        r.copy(cum2v);
                        r.conj();
                        t.copy(cumv);
                        t.xtr_A(cu, cv, r);
                        cum2v.copy(cumv);
                        cum2v.xtr_D();
                        cumv.copy(t);
                        cu.xtr_D();
                    }
                }
            }
            r.copy(cv);
            r.xtr_A(cu, cumv, cum2v);
            for (i = 0; i < f2; i++) {
                r.xtr_D();
            }
            r = r.xtr_pow(d);
            return r;
        }
    };

    return FP4;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports.FP4 = FP4;
}

},{}],"./fp":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* Finite Field arithmetic */
/* AMCL mod p functions */

var FP = function(ctx) {
    "use strict";

    /* General purpose Constructor */
    var FP = function(x) {
        if (x instanceof FP) {
            this.f = new ctx.BIG(x.f);
            this.XES = x.XES;
        } else {
            this.f = new ctx.BIG(x);
            this.nres();
        }
    };

    FP.NOT_SPECIAL = 0;
    FP.PSEUDO_MERSENNE = 1;
    FP.GENERALISED_MERSENNE = 2;
    FP.MONTGOMERY_FRIENDLY = 3;

    FP.MODBITS = ctx.config["@NBT"];
    FP.MOD8 = ctx.config["@M8"];
    FP.MODTYPE = ctx.config["@MT"];

    FP.FEXCESS = (1 << ctx.config["@SH"]); // 2^(BASEBITS*NLEN-MODBITS)
    FP.OMASK = (-1) << FP.TBITS;
    FP.TBITS = FP.MODBITS % ctx.BIG.BASEBITS;
    FP.TMASK = (1 << FP.TBITS) - 1;

    FP.prototype = {
        /* set this=0 */
        zero: function() {
            this.XES = 1;
            this.f.zero();
        },

        /* copy from a ctx.BIG in ROM */
        rcopy: function(y) {
            this.f.rcopy(y);
            this.nres();
        },

        /* copy from another ctx.BIG */
        bcopy: function(y) {
            this.f.copy(y);
            this.nres();
            //alert("4. f= "+this.f.toString());
        },

        /* copy from another FP */
        copy: function(y) {
            this.XES = y.XES;
            this.f.copy(y.f);
        },

        /* conditional swap of a and b depending on d */
        cswap: function(b, d) {
            this.f.cswap(b.f, d);
            var t, c = d;
            c = ~(c - 1);
            t = c & (this.XES ^ b.XES);
            this.XES ^= t;
            b.XES ^= t;
        },

        /* conditional copy of b to a depending on d */
        cmove: function(b, d) {
            var c = d;

            c = ~(c - 1);

            this.f.cmove(b.f, d);
            this.XES ^= (this.XES ^ b.XES) & c;
        },

        /* convert to Montgomery n-residue form */
        nres: function() {
            var r, d;

            if (FP.MODTYPE != FP.PSEUDO_MERSENNE && FP.MODTYPE != FP.GENERALISED_MERSENNE) {
                r = new ctx.BIG();
                r.rcopy(ctx.ROM_FIELD.R2modp);

                d = ctx.BIG.mul(this.f, r);
                this.f.copy(FP.mod(d));
                this.XES = 2;
            } else {
                this.XES = 1;
            }

            return this;
        },

        /* convert back to regular form */
        redc: function() {
            var r = new ctx.BIG(0),
                d, w;

            r.copy(this.f);

            if (FP.MODTYPE != FP.PSEUDO_MERSENNE && FP.MODTYPE != FP.GENERALISED_MERSENNE) {
                d = new ctx.DBIG(0);
                d.hcopy(this.f);
                w = FP.mod(d);
                r.copy(w);
            }

            return r;
        },

        /* convert this to string */
        toString: function() {
            var s = this.redc().toString();
            return s;
        },

        /* test this=0 */
        iszilch: function() {
            this.reduce();
            return this.f.iszilch();
        },

        /* reduce this mod Modulus */
        reduce: function() {
            var p = new ctx.BIG(0);
            p.rcopy(ctx.ROM_FIELD.Modulus);
            this.f.mod(p);
            this.XES = 1;
        },

        /* set this=1 */
        one: function() {
            this.f.one();
            return this.nres();
        },

        /* normalise this */
        norm: function() {
            return this.f.norm();
        },

        /* this*=b mod Modulus */
        mul: function(b) {
            var d;

            if (this.XES * b.XES > FP.FEXCESS) {
                this.reduce();
            }

            d = ctx.BIG.mul(this.f, b.f);
            this.f.copy(FP.mod(d));
            this.XES = 2;

            return this;
        },

        /* this*=c mod Modulus where c is an int */
        imul: function(c) {
            var s = false,
                d, n;

            //this.norm();
            if (c < 0) {
                c = -c;
                s = true;
            }

            if (FP.MODTYPE == FP.PSEUDO_MERSENNE || FP.MODTYPE == FP.GENERALISED_MERSENNE) {
                d = this.f.pxmul(c);
                this.f.copy(FP.mod(d));
                this.XES = 2;
            } else {
                if (this.XES * c <= FP.FEXCESS) {
                    this.f.pmul(c);
                    this.XES *= c;
                } else {
                    n = new FP(c);
                    this.mul(n);
                }
            }

            /*
                    if (c<=ctx.BIG.NEXCESS && this.XES*c<=FP.FEXCESS)
                    {
                        this.f.imul(c);
                        this.XES*=c;
                        this.norm();
                    }
                    else
                    {
            //          var p=new ctx.BIG(0);
            //          p.rcopy(ctx.ROM_FIELD.Modulus);
                        var d=this.f.pxmul(c);
                        this.f.copy(FP.mod(d));
                    }
            */
            if (s) {
                this.neg();
                this.norm();
            }
            return this;
        },

        /* this*=this mod Modulus */
        sqr: function() {
            var d, t;

            if (this.XES * this.XES > FP.FEXCESS) {
                this.reduce();
            }
            //if ((ea+1)>= Math.floor((FP.FEXCESS-1)/(ea+1))) this.reduce();

            d = ctx.BIG.sqr(this.f);
            t = FP.mod(d);
            this.f.copy(t);
            this.XES = 2;

            return this;
        },

        /* this+=b */
        add: function(b) {
            this.f.add(b.f);
            this.XES += b.XES;

            if (this.XES > FP.FEXCESS) {
                this.reduce();
            }

            return this;
        },
        /* this=-this mod Modulus */
        neg: function() {
            var m = new ctx.BIG(0),
                sb;

            m.rcopy(ctx.ROM_FIELD.Modulus);

            sb = FP.logb2(this.XES - 1);

            m.fshl(sb);
            this.XES = (1 << sb);
            this.f.rsub(m);

            if (this.XES > FP.FEXCESS) {
                this.reduce();
            }

            return this;
        },

        /* this-=b */
        sub: function(b) {
            var n = new FP(0);

            n.copy(b);
            n.neg();
            this.add(n);

            return this;
        },

        rsub: function(b) {
            var n = new FP(0);

            n.copy(this);
            n.neg();
            this.copy(b);
            this.add(n);
        },

        /* this/=2 mod Modulus */
        div2: function() {
            var p;

            if (this.f.parity() === 0) {
                this.f.fshr(1);
            } else {
                p = new ctx.BIG(0);
                p.rcopy(ctx.ROM_FIELD.Modulus);

                this.f.add(p);
                this.f.norm();
                this.f.fshr(1);
            }

            return this;
        },

        /* this=1/this mod Modulus */
        inverse: function() {
            var p = new ctx.BIG(0),
                r = this.redc();

            p.rcopy(ctx.ROM_FIELD.Modulus);
            r.invmodp(p);
            this.f.copy(r);

            return this.nres();
        },

        /* return TRUE if this==a */
        equals: function(a) {
            a.reduce();
            this.reduce();

            if (ctx.BIG.comp(a.f, this.f) === 0) {
                return true;
            }

            return false;
        },

        /* return this^e mod Modulus */
        pow: function(e) {
            var bt,
                r = new FP(1),
                m = new FP(0);

            e.norm();
            this.norm();
            m.copy(this);

            for (;;) {
                bt = e.parity();
                e.fshr(1);

                if (bt == 1) {
                    r.mul(m);
                }

                if (e.iszilch()) {
                    break;
                }

                m.sqr();
            }

            r.reduce();

            return r;
        },

        /* return jacobi symbol (this/Modulus) */
        jacobi: function() {
            var p = new ctx.BIG(0),
                w = this.redc();

            p.rcopy(ctx.ROM_FIELD.Modulus);

            return w.jacobi(p);
        },

        /* return sqrt(this) mod Modulus */
        sqrt: function() {
            var b = new ctx.BIG(0),
                i, v, r;

            this.reduce();

            b.rcopy(ctx.ROM_FIELD.Modulus);

            if (FP.MOD8 == 5) {
                b.dec(5);
                b.norm();
                b.shr(3);
                i = new FP(0);
                i.copy(this);
                i.f.shl(1);
                v = i.pow(b);
                i.mul(v);
                i.mul(v);
                i.f.dec(1);
                r = new FP(0);
                r.copy(this);
                r.mul(v);
                r.mul(i);
                r.reduce();

                return r;
            } else {
                b.inc(1);
                b.norm();
                b.shr(2);

                return this.pow(b);
            }
        }

    };

    FP.logb2 = function(v) {
        var r;

        v |= v >>> 1;
        v |= v >>> 2;
        v |= v >>> 4;
        v |= v >>> 8;
        v |= v >>> 16;

        v = v - ((v >>> 1) & 0x55555555);
        v = (v & 0x33333333) + ((v >>> 2) & 0x33333333);
        r = ((v + (v >>> 4) & 0xF0F0F0F) * 0x1010101) >>> 24;

        return r;
    };

    /* calculate Field Excess
    FP.EXCESS=function(a)
    {
        return ((a.w[ctx.BIG.NLEN-1]&FP.OMASK)>>(FP.MODBITS%ctx.BIG.BASEBITS))+1;
    };
    */

    /* reduce a ctx.DBIG to a ctx.BIG using a "special" modulus */
    FP.mod = function(d) {
        var b = new ctx.BIG(0),
            i, t, v, tw, tt, lo, carry, m, dd;

        if (FP.MODTYPE == FP.PSEUDO_MERSENNE) {
            t = d.split(FP.MODBITS);
            b.hcopy(d);

            if (ctx.ROM_FIELD.MConst != 1) {
                v = t.pmul(ctx.ROM_FIELD.MConst);
            } else {
                v = 0;
            }

            t.add(b);
            t.norm();

            tw = t.w[ctx.BIG.NLEN - 1];
            t.w[ctx.BIG.NLEN - 1] &= FP.TMASK;
            t.inc(ctx.ROM_FIELD.MConst * ((tw >> FP.TBITS) + (v << (ctx.BIG.BASEBITS - FP.TBITS))));
            //      b.add(t);
            t.norm();

            return t;
        }

        if (FP.MODTYPE == FP.MONTGOMERY_FRIENDLY) {
            for (i = 0; i < ctx.BIG.NLEN; i++) {
                d.w[ctx.BIG.NLEN + i] += d.muladd(d.w[i], ctx.ROM_FIELD.MConst - 1, d.w[i], ctx.BIG.NLEN + i - 1);
            }

            for (i = 0; i < ctx.BIG.NLEN; i++) {
                b.w[i] = d.w[ctx.BIG.NLEN + i];
            }

            b.norm();
        }

        if (FP.MODTYPE == FP.GENERALISED_MERSENNE) { // GoldiLocks Only
            t = d.split(FP.MODBITS);
            b.hcopy(d);
            b.add(t);
            dd = new ctx.DBIG(0);
            dd.hcopy(t);
            dd.shl(FP.MODBITS / 2);

            tt = dd.split(FP.MODBITS);
            lo = new ctx.BIG();
            lo.hcopy(dd);

            b.add(tt);
            b.add(lo);
            //b.norm();
            tt.shl(FP.MODBITS / 2);
            b.add(tt);

            carry = b.w[ctx.BIG.NLEN - 1] >> FP.TBITS;
            b.w[ctx.BIG.NLEN - 1] &= FP.TMASK;
            b.w[0] += carry;

            b.w[Math.floor(224 / ctx.BIG.BASEBITS)] += carry << (224 % ctx.BIG.BASEBITS);
            b.norm();
        }

        if (FP.MODTYPE == FP.NOT_SPECIAL) {
            m = new ctx.BIG(0);
            m.rcopy(ctx.ROM_FIELD.Modulus);

            b.copy(ctx.BIG.monty(m, ctx.ROM_FIELD.MConst, d));
        }

        return b;
    };

    return FP;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports.FP = FP;
}

},{}],"./gcm":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/*
 * Implementation of the ctx.AES-GCM Encryption/Authentication
 *
 * Some restrictions..
 * 1. Only for use with ctx.AES
 * 2. Returned tag is always 128-bits. Truncate at your own risk.
 * 3. The order of function calls must follow some rules
 *
 * Typical sequence of calls..
 * 1. call GCM_init
 * 2. call GCM_add_header any number of times, as long as length of header is multiple of 16 bytes (block size)
 * 3. call GCM_add_header one last time with any length of header
 * 4. call GCM_add_cipher any number of times, as long as length of cipher/plaintext is multiple of 16 bytes
 * 5. call GCM_add_cipher one last time with any length of cipher/plaintext
 * 6. call GCM_finish to extract the tag.
 *
 * See http://www.mindspring.com/~dmcgrew/gcm-nist-6.pdf
 */

var GCM = function(ctx) {
    "use strict";

    var GCM = function() {
        this.table = new Array(128);
        for (var i = 0; i < 128; i++) {
            this.table[i] = new Array(4); /* 2k bytes */
        }
        this.stateX = [];
        this.Y_0 = [];
        this.counter = 0;
        this.lenA = [];
        this.lenC = [];
        this.status = 0;
        this.a = new ctx.AES();
    };

    // GCM constants

    GCM.ACCEPTING_HEADER = 0;
    GCM.ACCEPTING_CIPHER = 1;
    GCM.NOT_ACCEPTING_MORE = 2;
    GCM.FINISHED = 3;
    GCM.ENCRYPTING = 0;
    GCM.DECRYPTING = 1;

    GCM.prototype = {
        precompute: function(H) {
            var b = [],
                i, j, c;

            for (i = j = 0; i < 4; i++, j += 4) {
                b[0] = H[j];
                b[1] = H[j + 1];
                b[2] = H[j + 2];
                b[3] = H[j + 3];
                this.table[0][i] = GCM.pack(b);
            }
            for (i = 1; i < 128; i++) {
                c = 0;
                for (j = 0; j < 4; j++) {
                    this.table[i][j] = c | (this.table[i - 1][j]) >>> 1;
                    c = this.table[i - 1][j] << 31;
                }

                if (c !== 0) {
                    this.table[i][0] ^= 0xE1000000; /* irreducible polynomial */
                }
            }
        },

        gf2mul: function() { /* gf2m mul - Z=H*X mod 2^128 */
            var P = [],
                b = [],
                i, j, m, k, c;

            P[0] = P[1] = P[2] = P[3] = 0;
            j = 8;
            m = 0;

            for (i = 0; i < 128; i++) {
                c = (this.stateX[m] >>> (--j)) & 1;
                c = ~c + 1;
                for (k = 0; k < 4; k++) {
                    P[k] ^= (this.table[i][k] & c);
                }

                if (j === 0) {
                    j = 8;
                    m++;
                    if (m == 16) {
                        break;
                    }
                }
            }

            for (i = j = 0; i < 4; i++, j += 4) {
                b = GCM.unpack(P[i]);
                this.stateX[j] = b[0];
                this.stateX[j + 1] = b[1];
                this.stateX[j + 2] = b[2];
                this.stateX[j + 3] = b[3];
            }
        },

        wrap: function() { /* Finish off GHASH */
            var F = [],
                L = [],
                b = [],
                i, j;

            /* convert lengths from bytes to bits */
            F[0] = (this.lenA[0] << 3) | (this.lenA[1] & 0xE0000000) >>> 29;
            F[1] = this.lenA[1] << 3;
            F[2] = (this.lenC[0] << 3) | (this.lenC[1] & 0xE0000000) >>> 29;
            F[3] = this.lenC[1] << 3;

            for (i = j = 0; i < 4; i++, j += 4) {
                b = GCM.unpack(F[i]);
                L[j] = b[0];
                L[j + 1] = b[1];
                L[j + 2] = b[2];
                L[j + 3] = b[3];
            }

            for (i = 0; i < 16; i++) {
                this.stateX[i] ^= L[i];
            }

            this.gf2mul();
        },

        /* Initialize GCM mode */
        init: function(nk, key, niv, iv) { /* iv size niv is usually 12 bytes (96 bits). ctx.AES key size nk can be 16,24 or 32 bytes */
            var H = [],
                b = [],
                i;

            for (i = 0; i < 16; i++) {
                H[i] = 0;
                this.stateX[i] = 0;
            }

            this.a.init(ctx.AES.ECB, nk, key, iv);
            this.a.ecb_encrypt(H); /* E(K,0) */
            this.precompute(H);

            this.lenA[0] = this.lenC[0] = this.lenA[1] = this.lenC[1] = 0;

            if (niv == 12) {
                for (i = 0; i < 12; i++) {
                    this.a.f[i] = iv[i];
                }

                b = GCM.unpack(1);
                this.a.f[12] = b[0];
                this.a.f[13] = b[1];
                this.a.f[14] = b[2];
                this.a.f[15] = b[3]; /* initialise IV */

                for (i = 0; i < 16; i++) {
                    this.Y_0[i] = this.a.f[i];
                }
            } else {
                this.status = GCM.ACCEPTING_CIPHER;
                this.ghash(iv, niv); /* GHASH(H,0,IV) */
                this.wrap();

                for (i = 0; i < 16; i++) {
                    this.a.f[i] = this.stateX[i];
                    this.Y_0[i] = this.a.f[i];
                    this.stateX[i] = 0;
                }

                this.lenA[0] = this.lenC[0] = this.lenA[1] = this.lenC[1] = 0;
            }

            this.status = GCM.ACCEPTING_HEADER;
        },

        /* Add Header data - included but not encrypted */
        add_header: function(header, len) { /* Add some header. Won't be encrypted, but will be authenticated. len is length of header */
            var i, j = 0;

            if (this.status != GCM.ACCEPTING_HEADER) {
                return false;
            }

            while (j < len) {
                for (i = 0; i < 16 && j < len; i++) {
                    this.stateX[i] ^= header[j++];
                    this.lenA[1]++;
                    this.lenA[1] |= 0;

                    if (this.lenA[1] === 0) {
                        this.lenA[0]++;
                    }
                }

                this.gf2mul();
            }

            if (len % 16 !== 0) {
                this.status = GCM.ACCEPTING_CIPHER;
            }

            return true;
        },

        ghash: function(plain, len) {
            var i, j = 0;

            if (this.status == GCM.ACCEPTING_HEADER) {
                this.status = GCM.ACCEPTING_CIPHER;
            }

            if (this.status != GCM.ACCEPTING_CIPHER) {
                return false;
            }

            while (j < len) {
                for (i = 0; i < 16 && j < len; i++) {
                    this.stateX[i] ^= plain[j++];
                    this.lenC[1]++;
                    this.lenC[1] |= 0;

                    if (this.lenC[1] === 0) {
                        this.lenC[0]++;
                    }
                }
                this.gf2mul();
            }

            if (len % 16 !== 0) {
                this.status = GCM.NOT_ACCEPTING_MORE;
            }

            return true;
        },

        /* Add Plaintext - included and encrypted */
        add_plain: function(plain, len) {
            var B = [],
                b = [],
                cipher = [],
                i, j = 0;

            if (this.status == GCM.ACCEPTING_HEADER) {
                this.status = GCM.ACCEPTING_CIPHER;
            }

            if (this.status != GCM.ACCEPTING_CIPHER) {
                return cipher;
            }

            while (j < len) {
                b[0] = this.a.f[12];
                b[1] = this.a.f[13];
                b[2] = this.a.f[14];
                b[3] = this.a.f[15];
                this.counter = GCM.pack(b);
                this.counter++;
                b = GCM.unpack(this.counter);
                this.a.f[12] = b[0];
                this.a.f[13] = b[1];
                this.a.f[14] = b[2];
                this.a.f[15] = b[3]; /* increment counter */

                for (i = 0; i < 16; i++) {
                    B[i] = this.a.f[i];
                }

                this.a.ecb_encrypt(B); /* encrypt it  */

                for (i = 0; i < 16 && j < len; i++) {
                    cipher[j] = (plain[j] ^ B[i]);
                    this.stateX[i] ^= cipher[j++];
                    this.lenC[1]++;
                    this.lenC[1] |= 0;

                    if (this.lenC[1] === 0) {
                        this.lenC[0]++;
                    }
                }

                this.gf2mul();
            }

            if (len % 16 !== 0) {
                this.status = GCM.NOT_ACCEPTING_MORE;
            }

            return cipher;
        },

        /* Add Ciphertext - decrypts to plaintext */
        add_cipher: function(cipher, len) {
            var B = [],
                b = [],
                plain = [],
                j = 0,
                i, oc;

            if (this.status == GCM.ACCEPTING_HEADER) {
                this.status = GCM.ACCEPTING_CIPHER;
            }

            if (this.status != GCM.ACCEPTING_CIPHER) {
                return plain;
            }

            while (j < len) {
                b[0] = this.a.f[12];
                b[1] = this.a.f[13];
                b[2] = this.a.f[14];
                b[3] = this.a.f[15];
                this.counter = GCM.pack(b);
                this.counter++;
                b = GCM.unpack(this.counter);
                this.a.f[12] = b[0];
                this.a.f[13] = b[1];
                this.a.f[14] = b[2];
                this.a.f[15] = b[3]; /* increment counter */

                for (i = 0; i < 16; i++) {
                    B[i] = this.a.f[i];
                }

                this.a.ecb_encrypt(B); /* encrypt it  */

                for (i = 0; i < 16 && j < len; i++) {
                    oc = cipher[j];
                    plain[j] = (cipher[j] ^ B[i]);
                    this.stateX[i] ^= oc;
                    j++;
                    this.lenC[1]++;
                    this.lenC[1] |= 0;

                    if (this.lenC[1] === 0) {
                        this.lenC[0]++;
                    }
                }

                this.gf2mul();
            }

            if (len % 16 !== 0) {
                this.status = GCM.NOT_ACCEPTING_MORE;
            }

            return plain;
        },

        /* Finish and extract Tag */
        finish: function(extract) { /* Finish off GHASH and extract tag (MAC) */
            var tag = [],
                i;

            this.wrap();
            /* extract tag */
            if (extract) {
                this.a.ecb_encrypt(this.Y_0); /* E(K,Y0) */

                for (i = 0; i < 16; i++) {
                    this.Y_0[i] ^= this.stateX[i];
                }

                for (i = 0; i < 16; i++) {
                    tag[i] = this.Y_0[i];
                    this.Y_0[i] = this.stateX[i] = 0;
                }
            }

            this.status = GCM.FINISHED;
            this.a.end();

            return tag;
        }

    };

    GCM.pack = function(b) { /* pack 4 bytes into a 32-bit Word */
        return (((b[0]) & 0xff) << 24) | ((b[1] & 0xff) << 16) | ((b[2] & 0xff) << 8) | (b[3] & 0xff);
    };

    GCM.unpack = function(a) { /* unpack bytes from a word */
        var b = [];

        b[3] = (a & 0xff);
        b[2] = ((a >>> 8) & 0xff);
        b[1] = ((a >>> 16) & 0xff);
        b[0] = ((a >>> 24) & 0xff);

        return b;
    };

    GCM.hex2bytes = function(s) {
        var len = s.length,
            data = [],
            i;

        for (i = 0; i < len; i += 2) {
            data[i / 2] = parseInt(s.substr(i, 2), 16);
        }

        return data;
    };

    return GCM;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports.GCM = GCM;
}

},{}],"./hash256":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

var HASH256 = function() {
    "use strict";

    var HASH256 = function() {
        this.length = [];
        this.h = [];
        this.w = [];
        this.init();
    };

    HASH256.prototype = {
        transform: function() { /* basic transformation step */
            var a, b, c, d, e, f, g, hh, t1, t2, j;

            for (j = 16; j < 64; j++) {
                this.w[j] = (HASH256.theta1(this.w[j - 2]) + this.w[j - 7] + HASH256.theta0(this.w[j - 15]) + this.w[j - 16]) | 0;
            }

            a = this.h[0];
            b = this.h[1];
            c = this.h[2];
            d = this.h[3];
            e = this.h[4];
            f = this.h[5];
            g = this.h[6];
            hh = this.h[7];

            for (j = 0; j < 64; j++) { /* 64 times - mush it up */
                t1 = (hh + HASH256.Sig1(e) + HASH256.Ch(e, f, g) + HASH256.HK[j] + this.w[j]) | 0;
                t2 = (HASH256.Sig0(a) + HASH256.Maj(a, b, c)) | 0;
                hh = g;
                g = f;
                f = e;
                e = (d + t1) | 0; // Need to knock these back down to prevent 52-bit overflow
                d = c;
                c = b;
                b = a;
                a = (t1 + t2) | 0;

            }
            this.h[0] += a;
            this.h[1] += b;
            this.h[2] += c;
            this.h[3] += d;
            this.h[4] += e;
            this.h[5] += f;
            this.h[6] += g;
            this.h[7] += hh;

        },

        /* Initialise Hash function */
        init: function() { /* initialise */
            var i;

            for (i = 0; i < 64; i++) {
                this.w[i] = 0;
            }
            this.length[0] = this.length[1] = 0;
            this.h[0] = HASH256.H[0];
            this.h[1] = HASH256.H[1];
            this.h[2] = HASH256.H[2];
            this.h[3] = HASH256.H[3];
            this.h[4] = HASH256.H[4];
            this.h[5] = HASH256.H[5];
            this.h[6] = HASH256.H[6];
            this.h[7] = HASH256.H[7];
        },

        /* process a single byte */
        process: function(byt) { /* process the next message byte */
            var cnt;

            cnt = (this.length[0] >>> 5) % 16;
            this.w[cnt] <<= 8;
            this.w[cnt] |= (byt & 0xFF);
            this.length[0] += 8;

            if ((this.length[0] & 0xffffffff) === 0) {
                this.length[1]++;
                this.length[0] = 0;
            }

            if ((this.length[0] % 512) === 0) {
                this.transform();
            }
        },

        /* process an array of bytes */
        process_array: function(b) {
            for (var i = 0; i < b.length; i++) {
                this.process(b[i]);
            }
        },

        /* process a 32-bit integer */
        process_num: function(n) {
            this.process((n >> 24) & 0xff);
            this.process((n >> 16) & 0xff);
            this.process((n >> 8) & 0xff);
            this.process(n & 0xff);
        },

        hash: function() { /* pad message and finish - supply digest */
            var digest = [],
                len0, len1, i;

            len0 = this.length[0];
            len1 = this.length[1];
            this.process(0x80);

            while ((this.length[0] % 512) != 448) {
                this.process(0);
            }

            this.w[14] = len1;
            this.w[15] = len0;
            this.transform();

            for (i = 0; i < HASH256.len; i++) { /* convert to bytes */
                digest[i] = ((this.h[i >>> 2] >> (8 * (3 - i % 4))) & 0xff);
            }
            this.init();

            return digest;
        }
    };

    /* static functions */

    HASH256.S = function(n, x) {
        return (((x) >>> n) | ((x) << (32 - n)));
    };

    HASH256.R = function(n, x) {
        return ((x) >>> n);
    };

    HASH256.Ch = function(x, y, z) {
        return ((x & y) ^ (~(x) & z));
    };

    HASH256.Maj = function(x, y, z) {
        return ((x & y) ^ (x & z) ^ (y & z));
    };

    HASH256.Sig0 = function(x) {
        return (HASH256.S(2, x) ^ HASH256.S(13, x) ^ HASH256.S(22, x));
    };

    HASH256.Sig1 = function(x) {
        return (HASH256.S(6, x) ^ HASH256.S(11, x) ^ HASH256.S(25, x));
    };

    HASH256.theta0 = function(x) {
        return (HASH256.S(7, x) ^ HASH256.S(18, x) ^ HASH256.R(3, x));
    };

    HASH256.theta1 = function(x) {
        return (HASH256.S(17, x) ^ HASH256.S(19, x) ^ HASH256.R(10, x));
    };

    /* constants */
    HASH256.len = 32;

    HASH256.H = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];

    HASH256.HK = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    return HASH256;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports.HASH256 = HASH256;
}

},{}],"./hash384":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

var HASH384 = function(ctx) {
    "use strict";

    var HASH384 = function() {
        this.length = [];
        this.h = [];
        this.w = [];
        this.init();
    };

    HASH384.prototype = {
        transform: function() { /* basic transformation step */
            var a, b, c, d, e, f, g, hh, t1, t2, j;

            for (j = 16; j < 80; j++) {
                this.w[j] = HASH384.theta1(this.w[j - 2]).add(this.w[j - 7]).add(HASH384.theta0(this.w[j - 15])).add(this.w[j - 16]);
            }

            a = this.h[0].copy();
            b = this.h[1].copy();
            c = this.h[2].copy();
            d = this.h[3].copy();
            e = this.h[4].copy();
            f = this.h[5].copy();
            g = this.h[6].copy();
            hh = this.h[7].copy();

            for (j = 0; j < 80; j++) { /* 80 times - mush it up */
                t1 = hh.copy();
                t1.add(HASH384.Sig1(e)).add(HASH384.Ch(e, f, g)).add(HASH384.HK[j]).add(this.w[j]);

                t2 = HASH384.Sig0(a);
                t2.add(HASH384.Maj(a, b, c));
                hh = g;
                g = f;
                f = e;
                e = d.copy();
                e.add(t1);

                d = c;
                c = b;
                b = a;
                a = t1.copy();
                a.add(t2);
            }

            this.h[0].add(a);
            this.h[1].add(b);
            this.h[2].add(c);
            this.h[3].add(d);
            this.h[4].add(e);
            this.h[5].add(f);
            this.h[6].add(g);
            this.h[7].add(hh);
        },

        /* Initialise Hash function */
        init: function() { /* initialise */
            var i;

            for (i = 0; i < 80; i++) {
                this.w[i] = new ctx.UInt64(0, 0);
            }
            this.length[0] = new ctx.UInt64(0, 0);
            this.length[1] = new ctx.UInt64(0, 0);
            this.h[0] = HASH384.H[0].copy();
            this.h[1] = HASH384.H[1].copy();
            this.h[2] = HASH384.H[2].copy();
            this.h[3] = HASH384.H[3].copy();
            this.h[4] = HASH384.H[4].copy();
            this.h[5] = HASH384.H[5].copy();
            this.h[6] = HASH384.H[6].copy();
            this.h[7] = HASH384.H[7].copy();
        },

        /* process a single byte */
        process: function(byt) { /* process the next message byte */
            var cnt, e;

            cnt = (this.length[0].bot >>> 6) % 16;
            this.w[cnt].shlb();
            this.w[cnt].bot |= (byt & 0xFF);

            e = new ctx.UInt64(0, 8);
            this.length[0].add(e);

            if (this.length[0].top === 0 && this.length[0].bot == 0) {
                e = new ctx.UInt64(0, 1);
                this.length[1].add(e);
            }

            if ((this.length[0].bot % 1024) === 0) {
                this.transform();
            }
        },

        /* process an array of bytes */
        process_array: function(b) {
            for (var i = 0; i < b.length; i++) {
                this.process(b[i]);
            }
        },

        /* process a 32-bit integer */
        process_num: function(n) {
            this.process((n >> 24) & 0xff);
            this.process((n >> 16) & 0xff);
            this.process((n >> 8) & 0xff);
            this.process(n & 0xff);
        },

        hash: function() { /* pad message and finish - supply digest */
            var digest = [],
                len0, len1,
                i;

            len0 = this.length[0].copy();
            len1 = this.length[1].copy();
            this.process(0x80);
            while ((this.length[0].bot % 1024) != 896) {
                this.process(0);
            }

            this.w[14] = len1;
            this.w[15] = len0;
            this.transform();

            for (i = 0; i < HASH384.len; i++) { /* convert to bytes */
                digest[i] = HASH384.R(8 * (7 - i % 8), this.h[i >>> 3]).bot & 0xff;
            }

            this.init();

            return digest;
        }
    };


    /* static  functions */
    HASH384.S = function(n, x) {
        if (n == 0) {
            return x;
        }

        if (n < 32) {
            return new ctx.UInt64((x.top >>> n) | (x.bot << (32 - n)), (x.bot >>> n) | (x.top << (32 - n)));
        } else {
            return new ctx.UInt64((x.bot >>> (n - 32)) | (x.top << (64 - n)), (x.top >>> (n - 32)) | (x.bot << (64 - n)));
        }

    };

    HASH384.R = function(n, x) {
        if (n == 0) {
            return x;
        }

        if (n < 32) {
            return new ctx.UInt64((x.top >>> n), (x.bot >>> n | (x.top << (32 - n))));
        } else {
            return new ctx.UInt64(0, x.top >>> (n - 32));
        }
    };

    HASH384.Ch = function(x, y, z) {
        return new ctx.UInt64((x.top & y.top) ^ (~(x.top) & z.top), (x.bot & y.bot) ^ (~(x.bot) & z.bot));
    };

    HASH384.Maj = function(x, y, z) {
        return new ctx.UInt64((x.top & y.top) ^ (x.top & z.top) ^ (y.top & z.top), (x.bot & y.bot) ^ (x.bot & z.bot) ^ (y.bot & z.bot));
    };

    HASH384.Sig0 = function(x) {
        var r1 = HASH384.S(28, x),
            r2 = HASH384.S(34, x),
            r3 = HASH384.S(39, x);

        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    HASH384.Sig1 = function(x) {
        var r1 = HASH384.S(14, x),
            r2 = HASH384.S(18, x),
            r3 = HASH384.S(41, x);

        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    HASH384.theta0 = function(x) {
        var r1 = HASH384.S(1, x),
            r2 = HASH384.S(8, x),
            r3 = HASH384.R(7, x);

        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    HASH384.theta1 = function(x) {
        var r1 = HASH384.S(19, x),
            r2 = HASH384.S(61, x),
            r3 = HASH384.R(6, x);

        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    HASH384.len = 48;

    HASH384.H = [new ctx.UInt64(0xcbbb9d5d, 0xc1059ed8), new ctx.UInt64(0x629a292a, 0x367cd507),
        new ctx.UInt64(0x9159015a, 0x3070dd17), new ctx.UInt64(0x152fecd8, 0xf70e5939),
        new ctx.UInt64(0x67332667, 0xffc00b31), new ctx.UInt64(0x8eb44a87, 0x68581511),
        new ctx.UInt64(0xdb0c2e0d, 0x64f98fa7), new ctx.UInt64(0x47b5481d, 0xbefa4fa4)
    ];

    HASH384.HK = [new ctx.UInt64(0x428a2f98, 0xd728ae22), new ctx.UInt64(0x71374491, 0x23ef65cd),
        new ctx.UInt64(0xb5c0fbcf, 0xec4d3b2f), new ctx.UInt64(0xe9b5dba5, 0x8189dbbc),
        new ctx.UInt64(0x3956c25b, 0xf348b538), new ctx.UInt64(0x59f111f1, 0xb605d019),
        new ctx.UInt64(0x923f82a4, 0xaf194f9b), new ctx.UInt64(0xab1c5ed5, 0xda6d8118),
        new ctx.UInt64(0xd807aa98, 0xa3030242), new ctx.UInt64(0x12835b01, 0x45706fbe),
        new ctx.UInt64(0x243185be, 0x4ee4b28c), new ctx.UInt64(0x550c7dc3, 0xd5ffb4e2),
        new ctx.UInt64(0x72be5d74, 0xf27b896f), new ctx.UInt64(0x80deb1fe, 0x3b1696b1),
        new ctx.UInt64(0x9bdc06a7, 0x25c71235), new ctx.UInt64(0xc19bf174, 0xcf692694),
        new ctx.UInt64(0xe49b69c1, 0x9ef14ad2), new ctx.UInt64(0xefbe4786, 0x384f25e3),
        new ctx.UInt64(0x0fc19dc6, 0x8b8cd5b5), new ctx.UInt64(0x240ca1cc, 0x77ac9c65),
        new ctx.UInt64(0x2de92c6f, 0x592b0275), new ctx.UInt64(0x4a7484aa, 0x6ea6e483),
        new ctx.UInt64(0x5cb0a9dc, 0xbd41fbd4), new ctx.UInt64(0x76f988da, 0x831153b5),
        new ctx.UInt64(0x983e5152, 0xee66dfab), new ctx.UInt64(0xa831c66d, 0x2db43210),
        new ctx.UInt64(0xb00327c8, 0x98fb213f), new ctx.UInt64(0xbf597fc7, 0xbeef0ee4),
        new ctx.UInt64(0xc6e00bf3, 0x3da88fc2), new ctx.UInt64(0xd5a79147, 0x930aa725),
        new ctx.UInt64(0x06ca6351, 0xe003826f), new ctx.UInt64(0x14292967, 0x0a0e6e70),
        new ctx.UInt64(0x27b70a85, 0x46d22ffc), new ctx.UInt64(0x2e1b2138, 0x5c26c926),
        new ctx.UInt64(0x4d2c6dfc, 0x5ac42aed), new ctx.UInt64(0x53380d13, 0x9d95b3df),
        new ctx.UInt64(0x650a7354, 0x8baf63de), new ctx.UInt64(0x766a0abb, 0x3c77b2a8),
        new ctx.UInt64(0x81c2c92e, 0x47edaee6), new ctx.UInt64(0x92722c85, 0x1482353b),
        new ctx.UInt64(0xa2bfe8a1, 0x4cf10364), new ctx.UInt64(0xa81a664b, 0xbc423001),
        new ctx.UInt64(0xc24b8b70, 0xd0f89791), new ctx.UInt64(0xc76c51a3, 0x0654be30),
        new ctx.UInt64(0xd192e819, 0xd6ef5218), new ctx.UInt64(0xd6990624, 0x5565a910),
        new ctx.UInt64(0xf40e3585, 0x5771202a), new ctx.UInt64(0x106aa070, 0x32bbd1b8),
        new ctx.UInt64(0x19a4c116, 0xb8d2d0c8), new ctx.UInt64(0x1e376c08, 0x5141ab53),
        new ctx.UInt64(0x2748774c, 0xdf8eeb99), new ctx.UInt64(0x34b0bcb5, 0xe19b48a8),
        new ctx.UInt64(0x391c0cb3, 0xc5c95a63), new ctx.UInt64(0x4ed8aa4a, 0xe3418acb),
        new ctx.UInt64(0x5b9cca4f, 0x7763e373), new ctx.UInt64(0x682e6ff3, 0xd6b2b8a3),
        new ctx.UInt64(0x748f82ee, 0x5defb2fc), new ctx.UInt64(0x78a5636f, 0x43172f60),
        new ctx.UInt64(0x84c87814, 0xa1f0ab72), new ctx.UInt64(0x8cc70208, 0x1a6439ec),
        new ctx.UInt64(0x90befffa, 0x23631e28), new ctx.UInt64(0xa4506ceb, 0xde82bde9),
        new ctx.UInt64(0xbef9a3f7, 0xb2c67915), new ctx.UInt64(0xc67178f2, 0xe372532b),
        new ctx.UInt64(0xca273ece, 0xea26619c), new ctx.UInt64(0xd186b8c7, 0x21c0c207),
        new ctx.UInt64(0xeada7dd6, 0xcde0eb1e), new ctx.UInt64(0xf57d4f7f, 0xee6ed178),
        new ctx.UInt64(0x06f067aa, 0x72176fba), new ctx.UInt64(0x0a637dc5, 0xa2c898a6),
        new ctx.UInt64(0x113f9804, 0xbef90dae), new ctx.UInt64(0x1b710b35, 0x131c471b),
        new ctx.UInt64(0x28db77f5, 0x23047d84), new ctx.UInt64(0x32caab7b, 0x40c72493),
        new ctx.UInt64(0x3c9ebe0a, 0x15c9bebc), new ctx.UInt64(0x431d67c4, 0x9c100d4c),
        new ctx.UInt64(0x4cc5d4be, 0xcb3e42b6), new ctx.UInt64(0x597f299c, 0xfc657e2a),
        new ctx.UInt64(0x5fcb6fab, 0x3ad6faec), new ctx.UInt64(0x6c44198c, 0x4a475817)
    ];

    return HASH384;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports.HASH384 = HASH384;
}

},{}],"./hash512":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

var HASH512 = function(ctx) {
    "use strict";

    var HASH512 = function() {
        this.length = [];
        this.h = [];
        this.w = [];
        this.init();
    };

    HASH512.prototype = {

        transform: function() { /* basic transformation step */
            var a, b, c, d, e, f, g, hh, t1, t2, j;

            for (j = 16; j < 80; j++) {
                this.w[j] = HASH512.theta1(this.w[j - 2]).add(this.w[j - 7]).add(HASH512.theta0(this.w[j - 15])).add(this.w[j - 16]);
            }

            a = this.h[0].copy();
            b = this.h[1].copy();
            c = this.h[2].copy();
            d = this.h[3].copy();
            e = this.h[4].copy();
            f = this.h[5].copy();
            g = this.h[6].copy();
            hh = this.h[7].copy();

            for (j = 0; j < 80; j++) { /* 80 times - mush it up */
                t1 = hh.copy();
                t1.add(HASH512.Sig1(e)).add(HASH512.Ch(e, f, g)).add(HASH512.HK[j]).add(this.w[j]);

                t2 = HASH512.Sig0(a);
                t2.add(HASH512.Maj(a, b, c));
                hh = g;
                g = f;
                f = e;
                e = d.copy();
                e.add(t1);

                d = c;
                c = b;
                b = a;
                a = t1.copy();
                a.add(t2);
            }

            this.h[0].add(a);
            this.h[1].add(b);
            this.h[2].add(c);
            this.h[3].add(d);
            this.h[4].add(e);
            this.h[5].add(f);
            this.h[6].add(g);
            this.h[7].add(hh);
        },

        /* Initialise Hash function */
        init: function() { /* initialise */
            var i;

            for (i = 0; i < 80; i++) {
                this.w[i] = new ctx.UInt64(0, 0);
            }

            this.length[0] = new ctx.UInt64(0, 0);
            this.length[1] = new ctx.UInt64(0, 0);
            this.h[0] = HASH512.H[0].copy();
            this.h[1] = HASH512.H[1].copy();
            this.h[2] = HASH512.H[2].copy();
            this.h[3] = HASH512.H[3].copy();
            this.h[4] = HASH512.H[4].copy();
            this.h[5] = HASH512.H[5].copy();
            this.h[6] = HASH512.H[6].copy();
            this.h[7] = HASH512.H[7].copy();
        },

        /* process a single byte */
        process: function(byt) { /* process the next message byte */
            var cnt, e;

            cnt = (this.length[0].bot >>> 6) % 16;
            this.w[cnt].shlb();
            this.w[cnt].bot |= (byt & 0xFF);

            e = new ctx.UInt64(0, 8);
            this.length[0].add(e);

            if (this.length[0].top === 0 && this.length[0].bot == 0) {
                e = new ctx.UInt64(0, 1);
                this.length[1].add(e);
            }

            if ((this.length[0].bot % 1024) === 0) {
                this.transform();
            }
        },

        /* process an array of bytes */
        process_array: function(b) {
            for (var i = 0; i < b.length; i++) {
                this.process(b[i]);
            }
        },

        /* process a 32-bit integer */
        process_num: function(n) {
            this.process((n >> 24) & 0xff);
            this.process((n >> 16) & 0xff);
            this.process((n >> 8) & 0xff);
            this.process(n & 0xff);
        },

        hash: function() { /* pad message and finish - supply digest */
            var digest = [],
                len0, len1, i;

            len0 = this.length[0].copy();
            len1 = this.length[1].copy();
            this.process(0x80);

            while ((this.length[0].bot % 1024) != 896) {
                this.process(0);
            }

            this.w[14] = len1;
            this.w[15] = len0;
            this.transform();

            for (i = 0; i < HASH512.len; i++) { /* convert to bytes */
                digest[i] = HASH512.R(8 * (7 - i % 8), this.h[i >>> 3]).bot & 0xff;
            }

            this.init();

            return digest;
        }
    };

    /* static functions */
    HASH512.S = function(n, x) {
        if (n == 0) {
            return x;
        }

        if (n < 32) {
            return new ctx.UInt64((x.top >>> n) | (x.bot << (32 - n)), (x.bot >>> n) | (x.top << (32 - n)));
        } else {
            return new ctx.UInt64((x.bot >>> (n - 32)) | (x.top << (64 - n)), (x.top >>> (n - 32)) | (x.bot << (64 - n)));
        }

    };

    HASH512.R = function(n, x) {
        if (n == 0) {
            return x;
        }

        if (n < 32) {
            return new ctx.UInt64((x.top >>> n), (x.bot >>> n | (x.top << (32 - n))));
        } else {
            return new ctx.UInt64(0, x.top >>> (n - 32));
        }
    };

    HASH512.Ch = function(x, y, z) {
        return new ctx.UInt64((x.top & y.top) ^ (~(x.top) & z.top), (x.bot & y.bot) ^ (~(x.bot) & z.bot));
    };

    HASH512.Maj = function(x, y, z) {
        return new ctx.UInt64((x.top & y.top) ^ (x.top & z.top) ^ (y.top & z.top), (x.bot & y.bot) ^ (x.bot & z.bot) ^ (y.bot & z.bot));
    };

    HASH512.Sig0 = function(x) {
        var r1 = HASH512.S(28, x),
            r2 = HASH512.S(34, x),
            r3 = HASH512.S(39, x);

        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    HASH512.Sig1 = function(x) {
        var r1 = HASH512.S(14, x),
            r2 = HASH512.S(18, x),
            r3 = HASH512.S(41, x);

        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    HASH512.theta0 = function(x) {
        var r1 = HASH512.S(1, x),
            r2 = HASH512.S(8, x),
            r3 = HASH512.R(7, x);

        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    HASH512.theta1 = function(x) {
        var r1 = HASH512.S(19, x),
            r2 = HASH512.S(61, x),
            r3 = HASH512.R(6, x);

        return new ctx.UInt64(r1.top ^ r2.top ^ r3.top, r1.bot ^ r2.bot ^ r3.bot);
    };

    /* constants */
    HASH512.len = 64;

    HASH512.H = [new ctx.UInt64(0x6a09e667, 0xf3bcc908), new ctx.UInt64(0xbb67ae85, 0x84caa73b),
        new ctx.UInt64(0x3c6ef372, 0xfe94f82b), new ctx.UInt64(0xa54ff53a, 0x5f1d36f1),
        new ctx.UInt64(0x510e527f, 0xade682d1), new ctx.UInt64(0x9b05688c, 0x2b3e6c1f),
        new ctx.UInt64(0x1f83d9ab, 0xfb41bd6b), new ctx.UInt64(0x5be0cd19, 0x137e2179)
    ];

    HASH512.HK = [new ctx.UInt64(0x428a2f98, 0xd728ae22), new ctx.UInt64(0x71374491, 0x23ef65cd),
        new ctx.UInt64(0xb5c0fbcf, 0xec4d3b2f), new ctx.UInt64(0xe9b5dba5, 0x8189dbbc),
        new ctx.UInt64(0x3956c25b, 0xf348b538), new ctx.UInt64(0x59f111f1, 0xb605d019),
        new ctx.UInt64(0x923f82a4, 0xaf194f9b), new ctx.UInt64(0xab1c5ed5, 0xda6d8118),
        new ctx.UInt64(0xd807aa98, 0xa3030242), new ctx.UInt64(0x12835b01, 0x45706fbe),
        new ctx.UInt64(0x243185be, 0x4ee4b28c), new ctx.UInt64(0x550c7dc3, 0xd5ffb4e2),
        new ctx.UInt64(0x72be5d74, 0xf27b896f), new ctx.UInt64(0x80deb1fe, 0x3b1696b1),
        new ctx.UInt64(0x9bdc06a7, 0x25c71235), new ctx.UInt64(0xc19bf174, 0xcf692694),
        new ctx.UInt64(0xe49b69c1, 0x9ef14ad2), new ctx.UInt64(0xefbe4786, 0x384f25e3),
        new ctx.UInt64(0x0fc19dc6, 0x8b8cd5b5), new ctx.UInt64(0x240ca1cc, 0x77ac9c65),
        new ctx.UInt64(0x2de92c6f, 0x592b0275), new ctx.UInt64(0x4a7484aa, 0x6ea6e483),
        new ctx.UInt64(0x5cb0a9dc, 0xbd41fbd4), new ctx.UInt64(0x76f988da, 0x831153b5),
        new ctx.UInt64(0x983e5152, 0xee66dfab), new ctx.UInt64(0xa831c66d, 0x2db43210),
        new ctx.UInt64(0xb00327c8, 0x98fb213f), new ctx.UInt64(0xbf597fc7, 0xbeef0ee4),
        new ctx.UInt64(0xc6e00bf3, 0x3da88fc2), new ctx.UInt64(0xd5a79147, 0x930aa725),
        new ctx.UInt64(0x06ca6351, 0xe003826f), new ctx.UInt64(0x14292967, 0x0a0e6e70),
        new ctx.UInt64(0x27b70a85, 0x46d22ffc), new ctx.UInt64(0x2e1b2138, 0x5c26c926),
        new ctx.UInt64(0x4d2c6dfc, 0x5ac42aed), new ctx.UInt64(0x53380d13, 0x9d95b3df),
        new ctx.UInt64(0x650a7354, 0x8baf63de), new ctx.UInt64(0x766a0abb, 0x3c77b2a8),
        new ctx.UInt64(0x81c2c92e, 0x47edaee6), new ctx.UInt64(0x92722c85, 0x1482353b),
        new ctx.UInt64(0xa2bfe8a1, 0x4cf10364), new ctx.UInt64(0xa81a664b, 0xbc423001),
        new ctx.UInt64(0xc24b8b70, 0xd0f89791), new ctx.UInt64(0xc76c51a3, 0x0654be30),
        new ctx.UInt64(0xd192e819, 0xd6ef5218), new ctx.UInt64(0xd6990624, 0x5565a910),
        new ctx.UInt64(0xf40e3585, 0x5771202a), new ctx.UInt64(0x106aa070, 0x32bbd1b8),
        new ctx.UInt64(0x19a4c116, 0xb8d2d0c8), new ctx.UInt64(0x1e376c08, 0x5141ab53),
        new ctx.UInt64(0x2748774c, 0xdf8eeb99), new ctx.UInt64(0x34b0bcb5, 0xe19b48a8),
        new ctx.UInt64(0x391c0cb3, 0xc5c95a63), new ctx.UInt64(0x4ed8aa4a, 0xe3418acb),
        new ctx.UInt64(0x5b9cca4f, 0x7763e373), new ctx.UInt64(0x682e6ff3, 0xd6b2b8a3),
        new ctx.UInt64(0x748f82ee, 0x5defb2fc), new ctx.UInt64(0x78a5636f, 0x43172f60),
        new ctx.UInt64(0x84c87814, 0xa1f0ab72), new ctx.UInt64(0x8cc70208, 0x1a6439ec),
        new ctx.UInt64(0x90befffa, 0x23631e28), new ctx.UInt64(0xa4506ceb, 0xde82bde9),
        new ctx.UInt64(0xbef9a3f7, 0xb2c67915), new ctx.UInt64(0xc67178f2, 0xe372532b),
        new ctx.UInt64(0xca273ece, 0xea26619c), new ctx.UInt64(0xd186b8c7, 0x21c0c207),
        new ctx.UInt64(0xeada7dd6, 0xcde0eb1e), new ctx.UInt64(0xf57d4f7f, 0xee6ed178),
        new ctx.UInt64(0x06f067aa, 0x72176fba), new ctx.UInt64(0x0a637dc5, 0xa2c898a6),
        new ctx.UInt64(0x113f9804, 0xbef90dae), new ctx.UInt64(0x1b710b35, 0x131c471b),
        new ctx.UInt64(0x28db77f5, 0x23047d84), new ctx.UInt64(0x32caab7b, 0x40c72493),
        new ctx.UInt64(0x3c9ebe0a, 0x15c9bebc), new ctx.UInt64(0x431d67c4, 0x9c100d4c),
        new ctx.UInt64(0x4cc5d4be, 0xcb3e42b6), new ctx.UInt64(0x597f299c, 0xfc657e2a),
        new ctx.UInt64(0x5fcb6fab, 0x3ad6faec), new ctx.UInt64(0x6c44198c, 0x4a475817)
    ];

    return HASH512;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports.HASH512 = HASH512;
}

},{}],"./mpin":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* MPIN API Functions */

var MPIN = function(ctx) {
    "use strict";

    var MPIN = {
        BAD_PARAMS: -11,
        INVALID_POINT: -14,
        WRONG_ORDER: -18,
        BAD_PIN: -19,
        /* configure PIN here */
        MAXPIN: 10000,
        /* max PIN */
        PBLEN: 14,
        /* MAXPIN length in bits */
        TS: 12,
        /* 10 for 4 digit PIN, 14 for 6-digit PIN - 2^TS/TS approx = sqrt(MAXPIN) */
        TRAP: 2000,
        /* 200 for 4 digit PIN, 2000 for 6-digit PIN  - approx 2*sqrt(MAXPIN) */
        EFS: ctx.BIG.MODBYTES,
        EGS: ctx.BIG.MODBYTES,
        PAS: 16,

        SHA256: 32,
        SHA384: 48,
        SHA512: 64,

        HASH_TYPE: 32,

        /* return time in slots since epoch */
        today: function() {
            var now = new Date();
            return Math.floor(now.getTime() / (60000 * 1440)); // for daily tokens
        },

        bytestostring: function(b) {
            var s = "",
                len = b.length,
                ch, i;

            for (i = 0; i < len; i++) {
                ch = b[i];
                s += ((ch >>> 4) & 15).toString(16);
                s += (ch & 15).toString(16);

            }

            return s;
        },

        stringtobytes: function(s) {
            var b = [],
                i;

            for (i = 0; i < s.length; i++) {
                b.push(s.charCodeAt(i));
            }

            return b;
        },

        comparebytes: function(a, b) {
            if (a.length != b.length) {
                return false;
            }

            for (var i = 0; i < a.length; i++) {
                if (a[i] != b[i]) {
                    return false;
                }
            }

            return true;
        },

        mpin_hash: function(sha, c, U) {
            var t = [],
                w = [],
                h = [],
                H, R, i;

            c.geta().getA().toBytes(w);
            for (i = 0; i < this.EFS; i++) {
                t[i] = w[i];
            }
            c.geta().getB().toBytes(w);
            for (i = this.EFS; i < 2 * this.EFS; i++) {
                t[i] = w[i - this.EFS];
            }
            c.getb().getA().toBytes(w);
            for (i = 2 * this.EFS; i < 3 * this.EFS; i++) {
                t[i] = w[i - 2 * this.EFS];
            }
            c.getb().getB().toBytes(w);
            for (i = 3 * this.EFS; i < 4 * this.EFS; i++) {
                t[i] = w[i - 3 * this.EFS];
            }

            U.getX().toBytes(w);
            for (i = 4 * this.EFS; i < 5 * this.EFS; i++) {
                t[i] = w[i - 4 * this.EFS];
            }
            U.getY().toBytes(w);
            for (i = 5 * this.EFS; i < 6 * this.EFS; i++) {
                t[i] = w[i - 5 * this.EFS];
            }

            if (sha == this.SHA256) {
                H = new ctx.HASH256();
            } else if (sha == this.SHA384) {
                H = new ctx.HASH384();
            } else if (sha == this.SHA512) {
                H = new ctx.HASH512();
            }

            H.process_array(t);
            h = H.hash();

            if (h.length == 0) {
                return null;
            }

            R = [];
            for (i = 0; i < this.PAS; i++) {
                R[i] = h[i];
            }

            return R;
        },

        /* Hash number (optional) and string to point on curve */
        hashit: function(sha, n, B) {
            var R = [],
                H, W, i, len;

            if (sha == this.SHA256) {
                H = new ctx.HASH256();
            } else if (sha == this.SHA384) {
                H = new ctx.HASH384();
            } else if (sha == this.SHA512) {
                H = new ctx.HASH512();
            }

            if (n > 0) {
                H.process_num(n);
            }
            H.process_array(B);
            R = H.hash();

            if (R.length == 0) {
                return null;
            }

            W = [];

            len = ctx.BIG.MODBYTES;

            if (sha >= len) {
                for (i = 0; i < len; i++) {
                    W[i] = R[i];
                }
            } else {
                for (i = 0; i < sha; i++) {
                    W[i + len - sha] = R[i];
                }

                for (i = 0; i < len - sha; i++) {
                    W[i] = 0;
                }
            }

            return W;
        },

        /* these next two functions help to implement elligator squared - http://eprint.iacr.org/2014/043 */
        /* maps a random u to a point on the curve */
        map: function(u, cb) {
            var P = new ctx.ECP(),
                x = new ctx.BIG(u),
                p = new ctx.BIG(0);

            p.rcopy(ctx.ROM_FIELD.Modulus);
            x.mod(p);

            for (;;) {
                P.setxi(x, cb);
                if (!P.is_infinity()) {
                    break;
                }
                x.inc(1);
                x.norm();
            }

            return P;
        },

        /* returns u derived from P. Random value in range 1 to return value should then be added to u */
        unmap: function(u, P) {
            var s = P.getS(),
                R = new ctx.ECP(),
                r = 0,
                x = P.getX();

            u.copy(x);

            for (;;) {
                u.dec(1);
                u.norm();
                r++;
                R.setxi(u, s); //=new ECP(u,s);
                if (!R.is_infinity()) {
                    break;
                }
            }

            return r;
        },

        /* these next two functions implement elligator squared - http://eprint.iacr.org/2014/043 */
        /* Elliptic curve point E in format (0x04,x,y} is converted to form {0x0-,u,v} */
        /* Note that u and v are indistinguishable from random strings */
        ENCODING: function(rng, E) {
            var T = [],
                i, rn, m, su, sv,
                u, v, P, p, W;

            for (i = 0; i < this.EFS; i++) {
                T[i] = E[i + 1];
            }
            u = ctx.BIG.fromBytes(T);
            for (i = 0; i < this.EFS; i++) {
                T[i] = E[i + this.EFS + 1];
            }
            v = ctx.BIG.fromBytes(T);

            P = new ctx.ECP(0);
            P.setxy(u, v);
            if (P.is_infinity()) {
                return this.INVALID_POINT;
            }

            p = new ctx.BIG(0);
            p.rcopy(ctx.ROM_FIELD.Modulus);
            u = ctx.BIG.randomnum(p, rng);

            su = rng.getByte();
            if (su < 0) {
                su = -su;
            }
            su %= 2;

            W = this.map(u, su);
            P.sub(W);
            sv = P.getS();
            rn = this.unmap(v, P);
            m = rng.getByte();
            if (m < 0) {
                m = -m;
            }
            m %= rn;
            v.inc(m + 1);
            E[0] = (su + 2 * sv);
            u.toBytes(T);
            for (i = 0; i < this.EFS; i++) {
                E[i + 1] = T[i];
            }
            v.toBytes(T);
            for (i = 0; i < this.EFS; i++) {
                E[i + this.EFS + 1] = T[i];
            }

            return 0;
        },

        DECODING: function(D) {
            var T = [],
                i, su, sv, u, v, W, P;

            if ((D[0] & 0x04) !== 0) {
                return this.INVALID_POINT;
            }

            for (i = 0; i < this.EFS; i++) {
                T[i] = D[i + 1];
            }
            u = ctx.BIG.fromBytes(T);
            for (i = 0; i < this.EFS; i++) {
                T[i] = D[i + this.EFS + 1];
            }
            v = ctx.BIG.fromBytes(T);

            su = D[0] & 1;
            sv = (D[0] >> 1) & 1;
            W = this.map(u, su);
            P = this.map(v, sv);
            P.add(W);
            u = P.getX();
            v = P.getY();
            D[0] = 0x04;
            u.toBytes(T);
            for (i = 0; i < this.EFS; i++) {
                D[i + 1] = T[i];
            }
            v.toBytes(T);
            for (i = 0; i < this.EFS; i++) {
                D[i + this.EFS + 1] = T[i];
            }

            return 0;
        },

        /* R=R1+R2 in group G1 */
        RECOMBINE_G1: function(R1, R2, R) {
            var P = ctx.ECP.fromBytes(R1),
                Q = ctx.ECP.fromBytes(R2);

            if (P.is_infinity() || Q.is_infinity()) {
                return this.INVALID_POINT;
            }

            P.add(Q);

            P.toBytes(R);

            return 0;
        },

        /* W=W1+W2 in group G2 */
        RECOMBINE_G2: function(W1, W2, W) {
            var P = ctx.ECP2.fromBytes(W1),
                Q = ctx.ECP2.fromBytes(W2);

            if (P.is_infinity() || Q.is_infinity()) {
                return this.INVALID_POINT;
            }

            P.add(Q);

            P.toBytes(W);

            return 0;
        },

        HASH_ID: function(sha, ID) {
            return this.hashit(sha, 0, ID);
        },

        /* create random secret S */
        RANDOM_GENERATE: function(rng, S) {
            var r = new ctx.BIG(0),
                s;

            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            s = ctx.BIG.randomnum(r, rng);
            //if (ROM.AES_S>0)
            //{
            //  s.mod2m(2*ROM.AES_S);
            //}
            s.toBytes(S);

            return 0;
        },

        /* Extract PIN from TOKEN for identity CID */
        EXTRACT_PIN: function(sha, CID, pin, TOKEN) {
            return this.EXTRACT_FACTOR(sha,CID,pin%this.MAXPIN,this.PBLEN,TOKEN);
        },

        /* Extract factor from TOKEN for identity CID */
        EXTRACT_FACTOR: function(sha, CID, factor, facbits, TOKEN) {
            var P, R, h;

            P = ctx.ECP.fromBytes(TOKEN);

            if (P.is_infinity()) {
                return this.INVALID_POINT;
            }

            h = this.hashit(sha, 0, CID);
            R = ctx.ECP.mapit(h);

            R = R.pinmul(factor, facbits);
            P.sub(R);

            P.toBytes(TOKEN);

            return 0;
        },

        /* Restore factor to TOKEN for identity CID */
        RESTORE_FACTOR: function(sha, CID, factor, facbits, TOKEN) {
            var P, R, h;

            P = ctx.ECP.fromBytes(TOKEN);

            if (P.is_infinity()) {
                return this.INVALID_POINT;
            }

            h = this.hashit(sha, 0, CID),
            R = ctx.ECP.mapit(h);

            R = R.pinmul(factor, facbits);
            P.add(R);

            P.toBytes(TOKEN);

            return 0;
        },

        /* Extract Server Secret SST=S*Q where Q is fixed generator in G2 and S is master secret */
        GET_SERVER_SECRET: function(S, SST) {
            var A = new ctx.BIG(0),
                B = new ctx.BIG(0),
                QX, QY, Q, s;

            A.rcopy(ctx.ROM_CURVE.CURVE_Pxa);
            B.rcopy(ctx.ROM_CURVE.CURVE_Pxb);
            QX = new ctx.FP2(0);
            QX.bset(A, B);
            A.rcopy(ctx.ROM_CURVE.CURVE_Pya);
            B.rcopy(ctx.ROM_CURVE.CURVE_Pyb);
            QY = new ctx.FP2(0);
            QY.bset(A, B);

            Q = new ctx.ECP2();
            Q.setxy(QX, QY);

            s = ctx.BIG.fromBytes(S);
            Q = ctx.PAIR.G2mul(Q, s);
            Q.toBytes(SST);

            return 0;
        },

        /*
         W=x*H(G);
         if RNG == NULL then X is passed in
         if RNG != NULL the X is passed out
         if type=0 W=x*G where G is point on the curve, else W=x*M(G), where M(G) is mapping of octet G to point on the curve
        */
        GET_G1_MULTIPLE: function(rng, type, X, G, W) {
            var r = new ctx.BIG(0),
                x, P;

            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            if (rng != null) {
                x = ctx.BIG.randomnum(r, rng);
                //if (ROM.AES_S>0)
                //{
                //  x.mod2m(2*ROM.AES_S);
                //}
                x.toBytes(X);
            } else {
                x = ctx.BIG.fromBytes(X);
            }

            if (type == 0) {
                P = ctx.ECP.fromBytes(G);
                if (P.is_infinity()) {
                    return this.INVALID_POINT;
                }
            } else {
                P = ctx.ECP.mapit(G);
            }

            ctx.PAIR.G1mul(P, x).toBytes(W);

            return 0;
        },


        /* Client secret CST=S*H(CID) where CID is client ID and S is master secret */
        GET_CLIENT_SECRET: function(S, CID, CST) {
            return this.GET_G1_MULTIPLE(null, 1, S, CID, CST);
        },

        /* Time Permit CTT=S*(date|H(CID)) where S is master secret */
        GET_CLIENT_PERMIT: function(sha, date, S, CID, CTT) {
            var h = this.hashit(sha, date, CID),
                P = ctx.ECP.mapit(h),
                s = ctx.BIG.fromBytes(S);

            P = ctx.PAIR.G1mul(P, s);
            P.toBytes(CTT);

            return 0;
        },

        /* Implement step 1 on client side of MPin protocol */
        CLIENT_1: function(sha, date, CLIENT_ID, rng, X, pin, TOKEN, SEC, xID, xCID, PERMIT) {
            var r = new ctx.BIG(0),
                x, P, T, W, h;

            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            //  var q=new ctx.BIG(0); q.rcopy(ctx.ROM_FIELD.Modulus);
            if (rng !== null) {
                x = ctx.BIG.randomnum(r, rng);
                //if (ROM.AES_S>0)
                //{
                //  x.mod2m(2*ROM.AES_S);
                //}
                x.toBytes(X);
            } else {
                x = ctx.BIG.fromBytes(X);
            }

            h = this.hashit(sha, 0, CLIENT_ID);
            P = ctx.ECP.mapit(h);
            T = ctx.ECP.fromBytes(TOKEN);
            if (T.is_infinity()) {
                return this.INVALID_POINT;
            }

            pin %= this.MAXPIN;
            W = P.pinmul(pin, this.PBLEN);
            T.add(W);

            if (date != 0) {
                W = ctx.ECP.fromBytes(PERMIT);

                if (W.is_infinity()) {
                    return this.INVALID_POINT;
                }

                T.add(W);
                h = this.hashit(sha, date, h);
                W = ctx.ECP.mapit(h);

                if (xID != null) {
                    P = ctx.PAIR.G1mul(P, x);
                    P.toBytes(xID);
                    W = ctx.PAIR.G1mul(W, x);
                    P.add(W);
                } else {
                    P.add(W);
                    P = ctx.PAIR.G1mul(P, x);
                }

                if (xCID != null) {
                    P.toBytes(xCID);
                }
            } else {
                if (xID != null) {
                    P = ctx.PAIR.G1mul(P, x);
                    P.toBytes(xID);
                }
            }

            T.toBytes(SEC);

            return 0;
        },

        /* Implement step 2 on client side of MPin protocol */
        CLIENT_2: function(X, Y, SEC) {
            var r = new ctx.BIG(0),
                P, px, py;

            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            P = ctx.ECP.fromBytes(SEC);
            if (P.is_infinity()) {
                return this.INVALID_POINT;
            }

            px = ctx.BIG.fromBytes(X);
            py = ctx.BIG.fromBytes(Y);
            px.add(py);
            px.mod(r);
            //  px.rsub(r);

            P = ctx.PAIR.G1mul(P, px);
            P.neg();
            P.toBytes(SEC);
            //ctx.PAIR.G1mul(P,px).toBytes(SEC);

            return 0;
        },

        /* Outputs H(CID) and H(T|H(CID)) for time permits. If no time permits set HID=HTID */
        SERVER_1: function(sha, date, CID, HID, HTID) {
            var h = this.hashit(sha, 0, CID),
                P = ctx.ECP.mapit(h),
                R;

            P.toBytes(HID);
            if (date !== 0) {
                //if (HID!=null) P.toBytes(HID);
                h = this.hashit(sha, date, h);
                R = ctx.ECP.mapit(h);
                P.add(R);
                P.toBytes(HTID);
            }
            //else P.toBytes(HID);
        },

        /* Implement step 1 of MPin protocol on server side. Pa is the client public key in case of DVS, otherwise must be set to null */
        SERVER_2: function(date, HID, HTID, Y, SST, xID, xCID, mSEC, E, F, Pa) {
            var Q,
                A, B, QX, QY,
                sQ, R, y, P, g;

            if (typeof Pa === "undefined" || Pa == null) {
                A = new ctx.BIG(0);
                B = new ctx.BIG(0);
                A.rcopy(ctx.ROM_CURVE.CURVE_Pxa);
                B.rcopy(ctx.ROM_CURVE.CURVE_Pxb);
                QX = new ctx.FP2(0);
                QX.bset(A, B);
                A.rcopy(ctx.ROM_CURVE.CURVE_Pya);
                B.rcopy(ctx.ROM_CURVE.CURVE_Pyb);
                QY = new ctx.FP2(0);
                QY.bset(A, B);

                Q = new ctx.ECP2();
                Q.setxy(QX, QY);
            } else {
                Q = ctx.ECP2.fromBytes(Pa);
                if (Q.is_infinity()) {
                    return this.INVALID_POINT;
                }
            }

            sQ = ctx.ECP2.fromBytes(SST);
            if (sQ.is_infinity()) {
                return this.INVALID_POINT;
            }

            if (date !== 0) {
                R = ctx.ECP.fromBytes(xCID);
            } else {
                if (xID == null) {
                    return this.BAD_PARAMS;
                }
                R = ctx.ECP.fromBytes(xID);
            }

            if (R.is_infinity()) {
                return this.INVALID_POINT;
            }

            y = ctx.BIG.fromBytes(Y);

            if (date != 0) {
                P = ctx.ECP.fromBytes(HTID);
            } else {
                if (HID == null) {
                    return this.BAD_PARAMS;
                }
                P = ctx.ECP.fromBytes(HID);
            }

            if (P.is_infinity()) {
                return this.INVALID_POINT;
            }

            P = ctx.PAIR.G1mul(P, y);
            P.add(R);
            P.affine();
            R = ctx.ECP.fromBytes(mSEC);
            if (R.is_infinity()) {
                return this.INVALID_POINT;
            }

            g = ctx.PAIR.ate2(Q, R, sQ, P);
            g = ctx.PAIR.fexp(g);

            if (!g.isunity()) {
                if (HID != null && xID != null && E != null && F != null) {
                    g.toBytes(E);

                    if (date !== 0) {
                        P = ctx.ECP.fromBytes(HID);
                        if (P.is_infinity()) {
                            return this.INVALID_POINT;
                        }

                        R = ctx.ECP.fromBytes(xID);
                        if (R.is_infinity()) {
                            return this.INVALID_POINT;
                        }

                        P = ctx.PAIR.G1mul(P, y);
                        P.add(R);
                        P.affine();
                    }
                    g = ctx.PAIR.ate(Q, P);
                    g = ctx.PAIR.fexp(g);

                    g.toBytes(F);
                }

                return this.BAD_PIN;
            }

            return 0;
        },

        /* Pollards kangaroos used to return PIN error */
        KANGAROO: function(E, F) {
            var ge = ctx.FP12.fromBytes(E),
                gf = ctx.FP12.fromBytes(F),
                distance = [],
                t = new ctx.FP12(gf),
                table = [],
                i, j, m, s, dn, dm, res, steps;

            s = 1;
            for (m = 0; m < this.TS; m++) {
                distance[m] = s;
                table[m] = new ctx.FP12(t);
                s *= 2;
                t.usqr();
            }
            t.one();
            dn = 0;
            for (j = 0; j < this.TRAP; j++) {
                i = t.geta().geta().getA().lastbits(20) % this.TS;
                t.mul(table[i]);
                dn += distance[i];
            }
            gf.copy(t);
            gf.conj();
            steps = 0;
            dm = 0;
            res = 0;
            while (dm - dn < this.MAXPIN) {
                steps++;
                if (steps > 4 * this.TRAP) {
                    break;
                }
                i = ge.geta().geta().getA().lastbits(20) % this.TS;
                ge.mul(table[i]);
                dm += distance[i];
                if (ge.equals(t)) {
                    res = dm - dn;
                    break;
                }
                if (ge.equals(gf)) {
                    res = dn - dm;
                    break;
                }

            }
            if (steps > 4 * this.TRAP || dm - dn >= this.MAXPIN) {
                res = 0;
            } // Trap Failed  - probable invalid token

            return res;
        },

        /* return time  since epoch */
        GET_TIME: function() {
            var now = new Date();
            return Math.floor(now.getTime() / (1000));
        },

        /* y = H(time,xCID) */
        GET_Y: function(sha, TimeValue, xCID, Y) {
            var q = new ctx.BIG(0),
                h = this.hashit(sha, TimeValue, xCID),
                y = ctx.BIG.fromBytes(h);

            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            y.mod(q);
            //if (ROM.AES_S>0)
            //{
            //  y.mod2m(2*ROM.AES_S);
            //}
            y.toBytes(Y);

            return 0;
        },

        /* One pass MPIN Client - DVS signature. Message must be null in case of One pass MPIN. */
        CLIENT: function(sha, date, CLIENT_ID, rng, X, pin, TOKEN, SEC, xID, xCID, PERMIT, TimeValue, Y, Message) {
            var rtn = 0,
                M = [],
                pID, i;

            if (date == 0) {
                pID = xID;
            } else {
                pID = xCID;
                xID = null;
            }

            rtn = this.CLIENT_1(sha, date, CLIENT_ID, rng, X, pin, TOKEN, SEC, xID, xCID, PERMIT);
            if (rtn != 0) {
                return rtn;
            }

            M = pID.slice();

            if (typeof Message !== "undefined" || Message != null) {
                for (i = 0; i < Message.length; i++) {
                    M.push(Message[i]);
                }
            }

            this.GET_Y(sha, TimeValue, M, Y);

            rtn = this.CLIENT_2(X, Y, SEC);
            if (rtn != 0) {
                return rtn;
            }

            return 0;
        },

        /* One pass MPIN Server */
        SERVER: function(sha, date, HID, HTID, Y, SST, xID, xCID, mSEC, E, F, CID, TimeValue, Message, Pa) {
            var rtn = 0,
                M = [],
                pID, i;

            if (date == 0) {
                pID = xID;
            } else {
                pID = xCID;
            }

            this.SERVER_1(sha, date, CID, HID, HTID);

            M = pID.slice();

            if (typeof Message !== "undefined" || Message != null) {
                for (i = 0; i < Message.length; i++) {
                    M.push(Message[i]);
                }
            }

            this.GET_Y(sha, TimeValue, M, Y);

            rtn = this.SERVER_2(date, HID, HTID, Y, SST, xID, xCID, mSEC, E, F, Pa);
            if (rtn != 0) {
                return rtn;
            }

            return 0;
        },

        /* Functions to support M-Pin Full */
        PRECOMPUTE: function(TOKEN, CID, G1, G2) {
            var P, T, g, A, B, QX, QY, Q;

            T = ctx.ECP.fromBytes(TOKEN);
            if (T.is_infinity()) {
                return this.INVALID_POINT;
            }

            P = ctx.ECP.mapit(CID);

            A = new ctx.BIG(0);
            B = new ctx.BIG(0);
            A.rcopy(ctx.ROM_CURVE.CURVE_Pxa);
            B.rcopy(ctx.ROM_CURVE.CURVE_Pxb);
            QX = new ctx.FP2(0);
            QX.bset(A, B);
            A.rcopy(ctx.ROM_CURVE.CURVE_Pya);
            B.rcopy(ctx.ROM_CURVE.CURVE_Pyb);
            QY = new ctx.FP2(0);
            QY.bset(A, B);

            Q = new ctx.ECP2();
            Q.setxy(QX, QY);

            g = ctx.PAIR.ate(Q, T);
            g = ctx.PAIR.fexp(g);
            g.toBytes(G1);

            g = ctx.PAIR.ate(Q, P);
            g = ctx.PAIR.fexp(g);
            g.toBytes(G2);

            return 0;
        },

        /* Hash the M-Pin transcript - new */

        HASH_ALL: function(sha, HID, xID, xCID, SEC, Y, R, W) {
            var tlen = 0,
                T = [],
                i;

            for (i = 0; i < HID.length; i++) {
                T[i] = HID[i];
            }
            tlen += HID.length;

            if (xCID != null) {
                for (i = 0; i < xCID.length; i++) {
                    T[i + tlen] = xCID[i];
                }
                tlen += xCID.length;
            } else {
                for (i = 0; i < xID.length; i++) {
                    T[i + tlen] = xID[i];
                }
                tlen += xID.length;
            }

            for (i = 0; i < SEC.length; i++) {
                T[i + tlen] = SEC[i];
            }
            tlen += SEC.length;

            for (i = 0; i < Y.length; i++) {
                T[i + tlen] = Y[i];
            }
            tlen += Y.length;

            for (i = 0; i < R.length; i++) {
                T[i + tlen] = R[i];
            }
            tlen += R.length;

            for (i = 0; i < W.length; i++) {
                T[i + tlen] = W[i];
            }
            tlen += W.length;

            return this.hashit(sha, 0, T);
        },

        /* calculate common key on client side */
        /* wCID = w.(A+AT) */
        CLIENT_KEY: function(sha, G1, G2, pin, R, X, H, wCID, CK) {
            var t = [],
                g1 = ctx.FP12.fromBytes(G1),
                g2 = ctx.FP12.fromBytes(G2),
                z = ctx.BIG.fromBytes(R),
                x = ctx.BIG.fromBytes(X),
                h = ctx.BIG.fromBytes(H),
                W = ctx.ECP.fromBytes(wCID),
                r, c, i;

            if (W.is_infinity()) {
                return this.INVALID_POINT;
            }

            W = ctx.PAIR.G1mul(W, x);

            //  var fa=new ctx.BIG(0); fa.rcopy(ctx.ROM_FIELD.Fra);
            //  var fb=new ctx.BIG(0); fb.rcopy(ctx.ROM_FIELD.Frb);
            //  var f=new ctx.FP2(fa,fb); //f.bset(fa,fb);

            r = new ctx.BIG(0);
            r.rcopy(ctx.ROM_CURVE.CURVE_Order);
            //  var q=new ctx.BIG(0); q.rcopy(ctx.ROM_FIELD.Modulus);

            z.add(h);
            z.mod(r);

            g2.pinpow(pin, this.PBLEN);
            g1.mul(g2);

            c = g1.compow(z, r);
            // var m=new ctx.BIG(q);
            // m.mod(r);

            // var a=new ctx.BIG(z);
            // a.mod(m);

            // var b=new ctx.BIG(z);
            // b.div(m);


            // var c=g1.trace();
            // g2.copy(g1);
            // g2.frob(f);
            // var cp=g2.trace();
            // g1.conj();
            // g2.mul(g1);
            // var cpm1=g2.trace();
            // g2.mul(g1);
            // var cpm2=g2.trace();

            // c=c.xtr_pow2(cp,cpm1,cpm2,a,b);

            t = this.mpin_hash(sha, c, W);

            for (i = 0; i < this.PAS; i++) {
                CK[i] = t[i];
            }

            return 0;
        },

        /* calculate common key on server side */
        /* Z=r.A - no time permits involved */

        SERVER_KEY: function(sha, Z, SST, W, H, HID, xID, xCID, SK) {
            var t = [],
                sQ, R, A, U, w, h, g, c, i;

            sQ = ctx.ECP2.fromBytes(SST);
            if (sQ.is_infinity()) {
                return this.INVALID_POINT;
            }

            R = ctx.ECP.fromBytes(Z);
            if (R.is_infinity()) {
                return this.INVALID_POINT;
            }

            A = ctx.ECP.fromBytes(HID);
            if (A.is_infinity()) {
                return this.INVALID_POINT;
            }

            if (xCID != null) {
                U = ctx.ECP.fromBytes(xCID);
            } else {
                U = ctx.ECP.fromBytes(xID);
            }

            if (U.is_infinity()) {
                return this.INVALID_POINT;
            }

            w = ctx.BIG.fromBytes(W);
            h = ctx.BIG.fromBytes(H);
            A = ctx.PAIR.G1mul(A, h);
            R.add(A);
            R.affine();

            U = ctx.PAIR.G1mul(U, w);
            g = ctx.PAIR.ate(sQ, R);
            g = ctx.PAIR.fexp(g);

            c = g.trace();

            t = this.mpin_hash(sha, c, U);

            for (i = 0; i < this.PAS; i++) {
                SK[i] = t[i];
            }

            return 0;
        },

        /* Generate a public key and the corresponding z for the key-escrow less scheme */
        /*
            if R==NULL then Z is passed in
            if R!=NULL then Z is passed out
            Pa=(z^-1).Q
        */
        GET_DVS_KEYPAIR: function(rng, Z, Pa) {
            var r = new ctx.BIG(0),
                z, A, B, QX, QY, Q;

            r.rcopy(ctx.ROM_CURVE.CURVE_Order);

            if (rng != null) {
                z = ctx.BIG.randomnum(r, rng);
                z.toBytes(Z);
            } else {
                z = ctx.BIG.fromBytes(Z);
            }
            z.invmodp(r);

            A = new ctx.BIG(0);
            B = new ctx.BIG(0);
            A.rcopy(ctx.ROM_CURVE.CURVE_Pxa);
            B.rcopy(ctx.ROM_CURVE.CURVE_Pxb);
            QX = new ctx.FP2(0);
            QX.bset(A, B);
            A.rcopy(ctx.ROM_CURVE.CURVE_Pya);
            B.rcopy(ctx.ROM_CURVE.CURVE_Pyb);
            QY = new ctx.FP2(0);
            QY.bset(A, B);

            Q = new ctx.ECP2();
            Q.setxy(QX, QY);
            if (Q.INF) {
                return MPIN.INVALID_POINT;
            }

            Q = ctx.PAIR.G2mul(Q, z);
            Q.toBytes(Pa);

            return 0;
        }
    };

    return MPIN;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports.MPIN = MPIN;
}

},{}],"./newhope":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

var NewHope = function() {
    "use strict";

    var NewHope = {
        //q=12289
        PRIME: 0x3001, // q in Hex
        LGN: 10, // Degree n=2^LGN
        ND: 0x3002FFF, // 1/(R-q) mod R
        ONE: 0x2AAC, // R mod q
        R2MODP: 0x1DA2, // R^2 mod q

        MODINV: Math.pow(2, -26),

        DEGREE: 1024,
        WL: 26,

        inv: 0xffb,
        invpr: 0x1131,

        roots: [0x2aac, 0xd6f, 0x1c67, 0x2c5b, 0x2dbd, 0x2697, 0x29f6, 0x8d3, 0x1b7c, 0x9eb, 0x20eb, 0x264a, 0x27d0, 0x121b, 0x58c, 0x4d7, 0x17a2, 0x29eb, 0x1b72, 0x13b0, 0x19b1, 0x1581, 0x2ac9, 0x25e8, 0x249d, 0x2d5e, 0x363, 0x1f74, 0x1f8f, 0x20a4, 0x2cb2, 0x2d04, 0x1407, 0x2df9, 0x3ad, 0x23f7, 0x1a72, 0xa91, 0x37f, 0xdb3, 0x2315, 0x5e6, 0xa8f, 0x211d, 0xdad, 0x1f2b, 0x2e29, 0x26b0, 0x2009, 0x2fdd, 0x2881, 0x399, 0x586, 0x2781, 0x2ab5, 0x971, 0x234b, 0x1df3, 0x1d2a, 0x15dd, 0x1a6d, 0x2774, 0x7ff, 0x1ebe, 0x230, 0x1cf4, 0x180b, 0xb58, 0x198c, 0x2b40, 0x127b, 0x1d9d, 0x137f, 0xfa0, 0x144, 0x4b, 0x2fac, 0xb09, 0x1c7f, 0x1b5, 0xeec, 0xc58, 0x1248, 0x243c, 0x108a, 0x14b8, 0xe9, 0x2dfe, 0xfb, 0x2602, 0x2aec, 0x1bb7, 0x1098, 0x23d8, 0x783, 0x1b13, 0x2067, 0x20d6, 0x171c, 0x4, 0x662, 0x1097, 0x24b9, 0x1b9d, 0x27c4, 0x276e, 0x6bf, 0x757, 0x2e16, 0x472, 0x1d11, 0x1649, 0x2904, 0xed4, 0x6c5, 0x14ae, 0x2ef8, 0x2ae0, 0x2e7c, 0x2735, 0x1186, 0x4f2, 0x17bb, 0x297f, 0x1dc7, 0x1ae5, 0x2a43, 0x2c02, 0xed6, 0x2b70, 0x1c7b, 0x18d1, 0x20ae, 0x6ad, 0x2404, 0x113a, 0x209e, 0x31b, 0x159d, 0x48f, 0xe09, 0x1bb2, 0x14f7, 0x385, 0x1c4, 0x1cdb, 0x22d6, 0x21d8, 0xc, 0x1aae, 0x2ece, 0x2d81, 0xd56, 0x5c1, 0x12da, 0x8cf, 0x1605, 0x1bc4, 0x18b7, 0x19b9, 0x21be, 0x135e, 0x28d6, 0x2891, 0x2208, 0x17e1, 0x2971, 0x926, 0x211b, 0xff, 0x51f, 0xa85, 0xe1, 0x2c35, 0x2585, 0x121, 0xe27, 0x2e64, 0x29f8, 0x2d46, 0xcb2, 0x292a, 0x33d, 0xaf9, 0xb86, 0x2e3a, 0x2138, 0x1978, 0x2324, 0xf3f, 0x2d10, 0x1dfd, 0x13c3, 0x6cc, 0x1a79, 0x1221, 0x250f, 0xacd, 0xfff, 0x7b4, 0x650, 0x1893, 0xe85, 0x1f5d, 0x12dc, 0x2d42, 0xd8e, 0x1240, 0x1082, 0x12ef, 0x11b6, 0xfa8, 0xb0f, 0xdac, 0x191c, 0x1242, 0x1ea, 0x155, 0x270a, 0x9ed, 0x2e5b, 0x25d8, 0x222c, 0x7e9, 0x1fb3, 0x10ac, 0x2919, 0x2584, 0xbe3, 0x24fa, 0x23ed, 0x618, 0x2d80, 0x6fa, 0x140e, 0x588, 0x355, 0x1054, 0x26c4, 0x1e4f, 0x1681, 0x1f6f, 0x1c53, 0xfe4, 0xacb, 0x1680, 0x2fe8, 0x6c, 0x165a, 0x10bb, 0x2c39, 0x1804, 0x1196, 0x884, 0x2622, 0x629, 0x1ac1, 0x2232, 0x2f9b, 0xd3e, 0x20ff, 0x12c0, 0x27ec, 0x5a, 0x2a0, 0x5f1, 0x1cda, 0x403, 0x1ea8, 0x1719, 0x1fc7, 0x2d23, 0x5ea, 0x25d1, 0xb6, 0x49c, 0xac7, 0x2d9c, 0x204e, 0x2142, 0x11e8, 0xed0, 0x15f0, 0x514, 0xa3f, 0xf43, 0x1de5, 0x2d97, 0x1543, 0x2c7b, 0x241a, 0x2223, 0x2fb8, 0x25b7, 0x1b4c, 0x2f36, 0x26e2, 0x100, 0x2555, 0x266c, 0x2e10, 0x271c, 0x5aa, 0x1789, 0x2199, 0x291d, 0x1088, 0x2046, 0x1ea1, 0xf89, 0x1c7a, 0x1e98, 0x137, 0x1b65, 0x24ed, 0xf37, 0x2ec3, 0xd0c, 0x7c7, 0x123f, 0xb2e, 0x1a97, 0x1a03, 0x1bcd, 0x3b2, 0x714, 0x2979, 0xaef, 0x2b3c, 0x2d91, 0xe03, 0xe5b, 0x1fbc, 0xcae, 0x432, 0x23a4, 0xb1d, 0x1ccc, 0x1fb6, 0x2f58, 0x2a5a, 0x723, 0x2c99, 0x2d70, 0xa, 0x263c, 0x2701, 0xdeb, 0x2d08, 0x1c34, 0x200c, 0x1e88, 0x396, 0x18d5, 0x1c45, 0xc4, 0x18bc, 0x2cd7, 0x1744, 0x8f1, 0x1c5c, 0xbe6, 0x2a89, 0x17a0, 0x207, 0x19ce, 0x2024, 0x23e3, 0x299b, 0x685, 0x2baf, 0x539, 0x2d49, 0x24b5, 0x158d, 0xfd, 0x2a95, 0x24d, 0xab3, 0x1125, 0x12f9, 0x15ba, 0x6a8, 0x2c36, 0x6e7, 0x1044, 0x36e, 0xfe8, 0x112d, 0x2717, 0x24a0, 0x1c09, 0xe1d, 0x828, 0x2f7, 0x1f5b, 0xfab, 0xcf6, 0x1332, 0x1c72, 0x2683, 0x15ce, 0x1ad3, 0x1a36, 0x24c, 0xb33, 0x253f, 0x1583, 0x1d69, 0x29ec, 0xba7, 0x2f97, 0x16df, 0x1068, 0xaee, 0xc4f, 0x153c, 0x24eb, 0x20cd, 0x1398, 0x2366, 0x11f9, 0xe77, 0x103d, 0x260a, 0xce, 0xaea, 0x236b, 0x2b11, 0x5f8, 0xe4f, 0x750, 0x1569, 0x10f5, 0x284e, 0xa38, 0x2e06, 0xe0, 0xeaa, 0x99e, 0x249b, 0x8eb, 0x2b97, 0x2fdf, 0x29c1, 0x1b00, 0x2fe3, 0x1d4f, 0x83f, 0x2d06, 0x10e, 0x183f, 0x27ba, 0x132, 0xfbf, 0x296d, 0x154a, 0x40a, 0x2767, 0xad, 0xc09, 0x974, 0x2821, 0x1e2e, 0x28d2, 0xfac, 0x3c4, 0x2f19, 0xdd4, 0x2ddf, 0x1e43, 0x1e90, 0x2dc9, 0x1144, 0x28c3, 0x653, 0xf3c, 0x1e32, 0x2a4a, 0x391, 0x1123, 0xdb, 0x2da0, 0xe1e, 0x667, 0x23b5, 0x2039, 0xa92, 0x1552, 0x5d3, 0x169a, 0x1f03, 0x1342, 0x2004, 0x1b5d, 0x2d01, 0x2e9b, 0x41f, 0x2bc7, 0xa94, 0xd0, 0x2e6a, 0x2b38, 0x14ac, 0x2724, 0x3ba, 0x6bc, 0x18ac, 0x2da5, 0x213c, 0x2c5c, 0xdd3, 0xaae, 0x2e08, 0x6cd, 0x1677, 0x2025, 0x1e1c, 0x5b4, 0xdc4, 0x60, 0x156c, 0x2669, 0x1c01, 0x26ab, 0x1ebb, 0x26d4, 0x21e1, 0x156b, 0x567, 0x1a, 0x29ce, 0x23d4, 0x684, 0xb79, 0x1953, 0x1046, 0x1d8c, 0x17b5, 0x1c28, 0x1ce5, 0x2478, 0x18d8, 0x1b16, 0x2c2f, 0x21c9, 0x19bb, 0xbbc, 0x291b, 0x19f6, 0x1879, 0x2fe4, 0x58e, 0x294a, 0x19e8, 0x27c7, 0x2fba, 0x1a29, 0x2319, 0x1ecb, 0x203b, 0x2f05, 0x2b82, 0x192f, 0x26aa, 0x2482, 0xaed, 0x1216, 0x708, 0x11a1, 0xc22, 0x908, 0x28f8, 0x2427, 0x7f8, 0x172e, 0xf50, 0xaa8, 0x184a, 0x1f67, 0x22d1, 0xeba, 0x215b, 0xf47, 0x2877, 0xd5e, 0x8dc, 0x20d, 0x2dae, 0x1d3e, 0x775, 0xbf3, 0x872, 0x2667, 0x1ff6, 0xd9f, 0x13c4, 0x105, 0x65f, 0x21ec, 0x6dd, 0x1a09, 0xc6e, 0x1fd, 0x1426, 0xae3, 0x494, 0x2d82, 0x22cd, 0x25d6, 0x11c1, 0x1c, 0x2cae, 0x141f, 0x110a, 0x147, 0x2657, 0x23fd, 0x2f39, 0x360, 0x2294, 0x1f1e, 0xb73, 0xbfc, 0x2f17, 0x7ca, 0x2f63, 0xbf, 0x28c2, 0xc1a, 0x255e, 0x226e, 0x1aa8, 0x229e, 0x161a, 0x273, 0x106d, 0x2c40, 0x7cf, 0x1408, 0x7d8, 0x100a, 0x759, 0x1db4, 0x24be, 0x2ebb, 0xc17, 0x1894, 0x244e, 0x15bd, 0x748, 0x1fe9, 0x23d, 0x1da, 0x2be, 0x18a3, 0xc5c, 0x9f9, 0x3d5, 0x2ce4, 0x54, 0x2abf, 0x279c, 0x1e81, 0x2d59, 0x2847, 0x23f4, 0xda8, 0xa20, 0x258, 0x1cfe, 0x240c, 0x2c2e, 0x2790, 0x2dd5, 0x2bf2, 0x2e34, 0x1724, 0x211, 0x1009, 0x27b9, 0x6f9, 0x23d9, 0x19a2, 0x627, 0x156d, 0x169e, 0x7e7, 0x30f, 0x24b6, 0x5c2, 0x1ce4, 0x28dd, 0x20, 0x16ab, 0x1cce, 0x20a9, 0x2390, 0x2884, 0x2245, 0x5f7, 0xab7, 0x1b6a, 0x11e7, 0x2a53, 0x2f94, 0x294c, 0x1ee5, 0x1364, 0x1b9a, 0xff7, 0x5eb, 0x2c30, 0x1c02, 0x5a1, 0x1b87, 0x2402, 0x1cc8, 0x2ee1, 0x1fbe, 0x138c, 0x2487, 0x1bf8, 0xd96, 0x1d68, 0x2fb3, 0x1fc1, 0x1fcc, 0xd66, 0x953, 0x2141, 0x157a, 0x2477, 0x18e3, 0x2f30, 0x75e, 0x1de1, 0x14b2, 0x2faa, 0x1697, 0x2334, 0x12d1, 0xb76, 0x2aa8, 0x1e7a, 0xd5, 0x2c60, 0x26b8, 0x1753, 0x124a, 0x1f57, 0x1425, 0xd84, 0x1c05, 0x641, 0xf3a, 0x1b8c, 0xd7d, 0x2f52, 0x2f4, 0xc73, 0x151b, 0x1589, 0x1819, 0x1b18, 0xb9b, 0x1ae9, 0x2b1f, 0x2b44, 0x2f5a, 0x2d37, 0x2cb1, 0x26f5, 0x233e, 0x276f, 0x276, 0x1260, 0x2997, 0x9f2, 0x1c15, 0x1694, 0x11ac, 0x1e6d, 0x1bef, 0x2966, 0x18b2, 0x4fa, 0x2044, 0x1b70, 0x1f3e, 0x221e, 0x28ca, 0x1d56, 0x7ae, 0x98d, 0x238c, 0x17b8, 0xad3, 0x113f, 0x1f1b, 0x4d2, 0x1757, 0xcb1, 0x2ef1, 0x2e02, 0x17fc, 0x2f11, 0x2a74, 0x2029, 0x700, 0x154e, 0x1cef, 0x226a, 0x21bf, 0x27a6, 0x14bc, 0x2b2b, 0x2fc6, 0x13b6, 0x21e6, 0x1663, 0xcbd, 0x752, 0x1624, 0x881, 0x2fc0, 0x1276, 0xa7f, 0x274f, 0x2b53, 0x670, 0x1fb7, 0x1e41, 0x2a1e, 0x2612, 0x297, 0x19de, 0x18b, 0x249, 0x1c88, 0xe9e, 0x1ef1, 0x213, 0x47b, 0x1e20, 0x28c1, 0x1d5e, 0x977, 0x1dca, 0x990, 0x1df6, 0x2b62, 0x870, 0x1f4, 0x1829, 0x1e0a, 0x46, 0x1b9f, 0x2102, 0x16b, 0x1b32, 0x568, 0x2050, 0x15b4, 0x191a, 0x1dd0, 0x5df, 0x55c, 0x1d21, 0x19db, 0x12d9, 0xe96, 0x680, 0x2349, 0x9b9, 0x155d, 0xe31, 0x249f, 0x20f8, 0xb30, 0x337, 0x2da3, 0x11c3, 0x248f, 0x1cf9, 0x10ee, 0x6d8, 0x6eb, 0xa0d, 0x101b, 0x1ae4, 0x1801, 0x24cd, 0x813, 0x2e98, 0x1574, 0x50, 0x11da, 0x1802, 0xf56, 0x1839, 0x219c, 0x105b, 0x43b, 0x2c9, 0x917, 0x14c1, 0x1b79, 0xdab, 0x2ab9, 0x265c, 0x71a, 0x1d90, 0x89f, 0x2bc2, 0x2777, 0x1014, 0x1e64, 0x14b4, 0x692, 0xddb, 0x56e, 0x2190, 0x2d1b, 0x1016, 0x12d6, 0x1c81, 0x2628, 0x4a1, 0x1268, 0x2597, 0x2926, 0x7c5, 0x1dcd, 0x53f, 0x11a9, 0x1a41, 0x5a2, 0x1c65, 0x7e8, 0xd71, 0x29c8, 0x427, 0x32f, 0x5dc, 0x16b1, 0x2a1d, 0x1787, 0x2224, 0x620, 0x6a4, 0x1351, 0x1038, 0xe6c, 0x111b, 0x2f13, 0x441, 0x2cfd, 0x2f2f, 0xd25, 0x9b8, 0x1b24, 0x762, 0x19b6, 0x2611, 0x85e, 0xe37, 0x1f5, 0x503, 0x1c46, 0x23cc, 0x4bb, 0x243e, 0x122b, 0x28e2, 0x133e, 0x2db9, 0xdb2, 0x1a5c, 0x29a9, 0xca, 0x2113, 0x13d1, 0x15ec, 0x2079, 0x18da, 0x2d50, 0x2c45, 0xaa2, 0x135a, 0x800, 0x18f7, 0x17f3, 0x5fd, 0x1f5a, 0x2d0, 0x2cd1, 0x9ee, 0x218b, 0x19fd, 0x53b, 0x28c5, 0xe33, 0x1911, 0x26cc, 0x2018, 0x2f88, 0x1b01, 0x2637, 0x1cd9, 0x126b, 0x1a0b, 0x5b0, 0x24e0, 0xe82, 0xb1, 0x21f7, 0x1a16, 0x2f24, 0x1cb1, 0x1f7d, 0x28a0, 0x167e, 0xc3],
        iroots: [0x2aac, 0x2292, 0x3a6, 0x139a, 0x272e, 0x60b, 0x96a, 0x244, 0x2b2a, 0x2a75, 0x1de6, 0x831, 0x9b7, 0xf16, 0x2616, 0x1485, 0x2fd, 0x34f, 0xf5d, 0x1072, 0x108d, 0x2c9e, 0x2a3, 0xb64, 0xa19, 0x538, 0x1a80, 0x1650, 0x1c51, 0x148f, 0x616, 0x185f, 0x1143, 0x2802, 0x88d, 0x1594, 0x1a24, 0x12d7, 0x120e, 0xcb6, 0x2690, 0x54c, 0x880, 0x2a7b, 0x2c68, 0x780, 0x24, 0xff8, 0x951, 0x1d8, 0x10d6, 0x2254, 0xee4, 0x2572, 0x2a1b, 0xcec, 0x224e, 0x2c82, 0x2570, 0x158f, 0xc0a, 0x2c54, 0x208, 0x1bfa, 0x3ff, 0x5be, 0x151c, 0x123a, 0x682, 0x1846, 0x2b0f, 0x1e7b, 0x8cc, 0x185, 0x521, 0x109, 0x1b53, 0x293c, 0x212d, 0x6fd, 0x19b8, 0x12f0, 0x2b8f, 0x1eb, 0x28aa, 0x2942, 0x893, 0x83d, 0x1464, 0xb48, 0x1f6a, 0x299f, 0x2ffd, 0x18e5, 0xf2b, 0xf9a, 0x14ee, 0x287e, 0xc29, 0x1f69, 0x144a, 0x515, 0x9ff, 0x2f06, 0x203, 0x2f18, 0x1b49, 0x1f77, 0xbc5, 0x1db9, 0x23a9, 0x2115, 0x2e4c, 0x1382, 0x24f8, 0x55, 0x2fb6, 0x2ebd, 0x2061, 0x1c82, 0x1264, 0x1d86, 0x4c1, 0x1675, 0x24a9, 0x17f6, 0x130d, 0x2dd1, 0x29d8, 0x9df, 0x277d, 0x1e6b, 0x17fd, 0x3c8, 0x1f46, 0x19a7, 0x2f95, 0x19, 0x1981, 0x2536, 0x201d, 0x13ae, 0x1092, 0x1980, 0x11b2, 0x93d, 0x1fad, 0x2cac, 0x2a79, 0x1bf3, 0x2907, 0x281, 0x29e9, 0xc14, 0xb07, 0x241e, 0xa7d, 0x6e8, 0x1f55, 0x104e, 0x2818, 0xdd5, 0xa29, 0x1a6, 0x2614, 0x8f7, 0x2eac, 0x2e17, 0x1dbf, 0x16e5, 0x2255, 0x24f2, 0x2059, 0x1e4b, 0x1d12, 0x1f7f, 0x1dc1, 0x2273, 0x2bf, 0x1d25, 0x10a4, 0x217c, 0x176e, 0x29b1, 0x284d, 0x2002, 0x2534, 0xaf2, 0x1de0, 0x1588, 0x2935, 0x1c3e, 0x1204, 0x2f1, 0x20c2, 0xcdd, 0x1689, 0xec9, 0x1c7, 0x247b, 0x2508, 0x2cc4, 0x6d7, 0x234f, 0x2bb, 0x609, 0x19d, 0x21da, 0x2ee0, 0xa7c, 0x3cc, 0x2f20, 0x257c, 0x2ae2, 0x2f02, 0xee6, 0x26db, 0x690, 0x1820, 0xdf9, 0x770, 0x72b, 0x1ca3, 0xe43, 0x1648, 0x174a, 0x143d, 0x19fc, 0x2732, 0x1d27, 0x2a40, 0x22ab, 0x280, 0x133, 0x1553, 0x2ff5, 0xe29, 0xd2b, 0x1326, 0x2e3d, 0x2c7c, 0x1b0a, 0x144f, 0x21f8, 0x2b72, 0x1a64, 0x2ce6, 0xf63, 0x1ec7, 0xbfd, 0x2954, 0xf53, 0x1730, 0x1386, 0x491, 0x212b, 0x222e, 0x3a5, 0xec5, 0x25c, 0x1755, 0x2945, 0x2c47, 0x8dd, 0x1b55, 0x4c9, 0x197, 0x2f31, 0x256d, 0x43a, 0x2be2, 0x166, 0x300, 0x14a4, 0xffd, 0x1cbf, 0x10fe, 0x1967, 0x2a2e, 0x1aaf, 0x256f, 0xfc8, 0xc4c, 0x299a, 0x21e3, 0x261, 0x2f26, 0x1ede, 0x2c70, 0x5b7, 0x11cf, 0x20c5, 0x29ae, 0x73e, 0x1ebd, 0x238, 0x1171, 0x11be, 0x222, 0x222d, 0xe8, 0x2c3d, 0x2055, 0x72f, 0x11d3, 0x7e0, 0x268d, 0x23f8, 0x2f54, 0x89a, 0x2bf7, 0x1ab7, 0x694, 0x2042, 0x2ecf, 0x847, 0x17c2, 0x2ef3, 0x2fb, 0x27c2, 0x12b2, 0x1e, 0x1501, 0x640, 0x22, 0x46a, 0x2716, 0xb66, 0x2663, 0x2157, 0x2f21, 0x1fb, 0x25c9, 0x7b3, 0x1f0c, 0x1a98, 0x28b1, 0x21b2, 0x2a09, 0x4f0, 0xc96, 0x2517, 0x2f33, 0x9f7, 0x1fc4, 0x218a, 0x1e08, 0xc9b, 0x1c69, 0xf34, 0xb16, 0x1ac5, 0x23b2, 0x2513, 0x1f99, 0x1922, 0x6a, 0x245a, 0x615, 0x1298, 0x1a7e, 0xac2, 0x24ce, 0x2db5, 0x15cb, 0x152e, 0x1a33, 0x97e, 0x138f, 0x1ccf, 0x230b, 0x2056, 0x10a6, 0x2d0a, 0x27d9, 0x21e4, 0x13f8, 0xb61, 0x8ea, 0x1ed4, 0x2019, 0x2c93, 0x1fbd, 0x291a, 0x3cb, 0x2959, 0x1a47, 0x1d08, 0x1edc, 0x254e, 0x2db4, 0x56c, 0x2f04, 0x1a74, 0xb4c, 0x2b8, 0x2ac8, 0x452, 0x297c, 0x666, 0xc1e, 0xfdd, 0x1633, 0x2dfa, 0x1861, 0x578, 0x241b, 0x13a5, 0x2710, 0x18bd, 0x32a, 0x1745, 0x2f3d, 0x13bc, 0x172c, 0x2c6b, 0x1179, 0xff5, 0x13cd, 0x2f9, 0x2216, 0x900, 0x9c5, 0x2ff7, 0x291, 0x368, 0x28de, 0x5a7, 0xa9, 0x104b, 0x1335, 0x24e4, 0xc5d, 0x2bcf, 0x2353, 0x1045, 0x21a6, 0x21fe, 0x270, 0x4c5, 0x2512, 0x688, 0x28ed, 0x2c4f, 0x1434, 0x15fe, 0x156a, 0x24d3, 0x1dc2, 0x283a, 0x22f5, 0x13e, 0x20ca, 0xb14, 0x149c, 0x2eca, 0x1169, 0x1387, 0x2078, 0x1160, 0xfbb, 0x1f79, 0x6e4, 0xe68, 0x1878, 0x2a57, 0x8e5, 0x1f1, 0x995, 0xaac, 0x2f01, 0x91f, 0xcb, 0x14b5, 0xa4a, 0x49, 0xdde, 0xbe7, 0x386, 0x1abe, 0x26a, 0x121c, 0x20be, 0x25c2, 0x2aed, 0x1a11, 0x2131, 0x1e19, 0xebf, 0xfb3, 0x265, 0x253a, 0x2b65, 0x2f4b, 0xa30, 0x2a17, 0x2de, 0x103a, 0x18e8, 0x1159, 0x2bfe, 0x1327, 0x2a10, 0x2d61, 0x2fa7, 0x815, 0x1d41, 0xf02, 0x22c3, 0x66, 0xdcf, 0x1540, 0x2f3e, 0x1983, 0x761, 0x1084, 0x1350, 0xdd, 0x15eb, 0xe0a, 0x2f50, 0x217f, 0xb21, 0x2a51, 0x15f6, 0x1d96, 0x1328, 0x9ca, 0x1500, 0x79, 0xfe9, 0x935, 0x16f0, 0x21ce, 0x73c, 0x2ac6, 0x1604, 0xe76, 0x2613, 0x330, 0x2d31, 0x10a7, 0x2a04, 0x180e, 0x170a, 0x2801, 0x1ca7, 0x255f, 0x3bc, 0x2b1, 0x1727, 0xf88, 0x1a15, 0x1c30, 0xeee, 0x2f37, 0x658, 0x15a5, 0x224f, 0x248, 0x1cc3, 0x71f, 0x1dd6, 0xbc3, 0x2b46, 0xc35, 0x13bb, 0x2afe, 0x2e0c, 0x21ca, 0x27a3, 0x9f0, 0x164b, 0x289f, 0x14dd, 0x2649, 0x22dc, 0xd2, 0x304, 0x2bc0, 0xee, 0x1ee6, 0x2195, 0x1fc9, 0x1cb0, 0x295d, 0x29e1, 0xddd, 0x187a, 0x5e4, 0x1950, 0x2a25, 0x2cd2, 0x2bda, 0x639, 0x2290, 0x2819, 0x139c, 0x2a5f, 0x15c0, 0x1e58, 0x2ac2, 0x1234, 0x283c, 0x6db, 0xa6a, 0x1d99, 0x2b60, 0x9d9, 0x1380, 0x1d2b, 0x1feb, 0x2e6, 0xe71, 0x2a93, 0x2226, 0x296f, 0x1b4d, 0x119d, 0x1fed, 0x88a, 0x43f, 0x2762, 0x1271, 0x28e7, 0x9a5, 0x548, 0x2256, 0x1488, 0x1b40, 0x26ea, 0x2d38, 0x2bc6, 0x1fa6, 0xe65, 0x17c8, 0x20ab, 0x17ff, 0x1e27, 0x2fb1, 0x1a8d, 0x169, 0x27ee, 0xb34, 0x1800, 0x151d, 0x1fe6, 0x25f4, 0x2916, 0x2929, 0x1f13, 0x1308, 0xb72, 0x1e3e, 0x25e, 0x2cca, 0x24d1, 0xf09, 0xb62, 0x21d0, 0x1aa4, 0x2648, 0xcb8, 0x2981, 0x216b, 0x1d28, 0x1626, 0x12e0, 0x2aa5, 0x2a22, 0x1231, 0x16e7, 0x1a4d, 0xfb1, 0x2a99, 0x14cf, 0x2e96, 0xeff, 0x1462, 0x2fbb, 0x11f7, 0x17d8, 0x2e0d, 0x2791, 0x49f, 0x120b, 0x2671, 0x1237, 0x268a, 0x12a3, 0x740, 0x11e1, 0x2b86, 0x2dee, 0x1110, 0x2163, 0x1379, 0x2db8, 0x2e76, 0x1623, 0x2d6a, 0x9ef, 0x5e3, 0x11c0, 0x104a, 0x2991, 0x4ae, 0x8b2, 0x2582, 0x1d8b, 0x41, 0x2780, 0x19dd, 0x28af, 0x2344, 0x199e, 0xe1b, 0x1c4b, 0x3b, 0x4d6, 0x1b45, 0x85b, 0xe42, 0xd97, 0x1312, 0x1ab3, 0x2901, 0xfd8, 0x58d, 0xf0, 0x1805, 0x1ff, 0x110, 0x2350, 0x18aa, 0x2b2f, 0x10e6, 0x1ec2, 0x252e, 0x1849, 0xc75, 0x2674, 0x2853, 0x12ab, 0x737, 0xde3, 0x10c3, 0x1491, 0xfbd, 0x2b07, 0x174f, 0x69b, 0x1412, 0x1194, 0x1e55, 0x196d, 0x13ec, 0x260f, 0x66a, 0x1da1, 0x2d8b, 0x892, 0xcc3, 0x90c, 0x350, 0x2ca, 0xa7, 0x4bd, 0x4e2, 0x1518, 0x2466, 0x14e9, 0x17e8, 0x1a78, 0x1ae6, 0x238e, 0x2d0d, 0xaf, 0x2284, 0x1475, 0x20c7, 0x29c0, 0x13fc, 0x227d, 0x1bdc, 0x10aa, 0x1db7, 0x18ae, 0x949, 0x3a1, 0x2f2c, 0x1187, 0x559, 0x248b, 0x1d30, 0xccd, 0x196a, 0x57, 0x1b4f, 0x1220, 0x28a3, 0xd1, 0x171e, 0xb8a, 0x1a87, 0xec0, 0x26ae, 0x229b, 0x1035, 0x1040, 0x4e, 0x1299, 0x226b, 0x1409, 0xb7a, 0x1c75, 0x1043, 0x120, 0x1339, 0xbff, 0x147a, 0x2a60, 0x13ff, 0x3d1, 0x2a16, 0x200a, 0x1467, 0x1c9d, 0x111c, 0x6b5, 0x6d, 0x5ae, 0x1e1a, 0x1497, 0x254a, 0x2a0a, 0xdbc, 0x77d, 0xc71, 0xf58, 0x1333, 0x1956, 0x2fe1, 0x724, 0x131d, 0x2a3f, 0xb4b, 0x2cf2, 0x281a, 0x1963, 0x1a94, 0x29da, 0x165f, 0xc28, 0x2908, 0x848, 0x1ff8, 0x2df0, 0x18dd, 0x1cd, 0x40f, 0x22c, 0x871, 0x3d3, 0xbf5, 0x1303, 0x2da9, 0x25e1, 0x2259, 0xc0d, 0x7ba, 0x2a8, 0x1180, 0x865, 0x542, 0x2fad, 0x31d, 0x2c2c, 0x2608, 0x23a5, 0x175e, 0x2d43, 0x2e27, 0x2dc4, 0x1018, 0x28b9, 0x1a44, 0xbb3, 0x176d, 0x23ea, 0x146, 0xb43, 0x124d, 0x28a8, 0x1ff7, 0x2829, 0x1bf9, 0x2832, 0x3c1, 0x1f94, 0x2d8e, 0x19e7, 0xd63, 0x1559, 0xd93, 0xaa3, 0x23e7, 0x73f, 0x2f42, 0x9e, 0x2837, 0xea, 0x2405, 0x248e, 0x10e3, 0xd6d, 0x2ca1, 0xc8, 0xc04, 0x9aa, 0x2eba, 0x1ef7, 0x1be2, 0x353, 0x2fe5, 0x1e40, 0xa2b, 0xd34, 0x27f, 0x2b6d, 0x251e, 0x1bdb, 0x2e04, 0x2393, 0x15f8, 0x2924, 0xe15, 0x29a2, 0x2efc, 0x1c3d, 0x2262, 0x100b, 0x99a, 0x278f, 0x240e, 0x288c, 0x12c3, 0x253, 0x2df4, 0x2725, 0x22a3, 0x78a, 0x20ba, 0xea6, 0x2147, 0xd30, 0x109a, 0x17b7, 0x2559, 0x20b1, 0x18d3, 0x2809, 0xbda, 0x709, 0x26f9, 0x23df, 0x1e60, 0x28f9, 0x1deb, 0x2514, 0xb7f, 0x957, 0x16d2, 0x47f, 0xfc, 0xfc6, 0x1136, 0xce8, 0x15d8, 0x47, 0x83a, 0x1619, 0x6b7, 0x2a73, 0x1d, 0x1788, 0x160b, 0x6e6, 0x2445, 0x1646, 0xe38, 0x3d2, 0x14eb, 0x1729, 0xb89, 0x131c, 0x13d9, 0x184c, 0x1275, 0x1fbb, 0x16ae, 0x2488, 0x297d, 0xc2d, 0x633, 0x2fe7, 0x2a9a, 0x1a96, 0xe20, 0x92d, 0x1146, 0x956, 0x1400, 0x998, 0x1a95, 0x2fa1, 0x223d, 0x2a4d, 0x11e5, 0xfdc, 0x198a, 0x2934, 0x1f9, 0x2553],

        round: function(a, b) {
            return Math.floor((a + (b >> 1)) / b);
        },

        /* constant time absolute value */
        nabs: function(ix) {
            var mask = (ix >> 31);
            return (ix + mask) ^ mask;
        },

        /* Montgomery stuff */

        redc: function(T) {
            var m = ((T & 0x3ffffff) * NewHope.ND) & 0x3ffffff;
            return ((m * NewHope.PRIME + T) * NewHope.MODINV);
        },

        nres: function(x) {
            return this.redc(x * NewHope.R2MODP);
        },

        modmul: function(a, b) {
            return this.redc(a * b);
        },

        /* NTT code */
        /* Cooley-Tukey NTT */

        ntt: function(x) {
            var t = NewHope.DEGREE / 2,
                q = NewHope.PRIME,
                m, i, j, k,
                S, U, V;

            /* Convert to Montgomery form */
            for (j = 0; j < NewHope.DEGREE; j++) {
                x[j] = this.nres(x[j]);
            }

            m = 1;
            while (m < NewHope.DEGREE) {
                k = 0;
                for (i = 0; i < m; i++) {
                    S = NewHope.roots[m + i];
                    for (j = k; j < k + t; j++) {
                        U = x[j];
                        V = this.modmul(x[j + t], S);

                        x[j] = U + V;

                        x[j + t] = U + 2 * q - V;
                    }
                    k += 2 * t;
                }
                t /= 2;
                m *= 2;
            }
        },

        /* Gentleman-Sande INTT */

        intt: function(x) {
            var t = 1,
                q = NewHope.PRIME,
                m, i, j, k,
                S, U, V, W;

            m = NewHope.DEGREE / 2;
            while (m > 1) {
                k = 0;
                for (i = 0; i < m; i++) {
                    S = NewHope.iroots[m + i];
                    for (j = k; j < k + t; j++) {
                        U = x[j];
                        V = x[j + t];
                        x[j] = U + V;
                        W = U + NewHope.DEGREE * q - V;
                        x[j + t] = this.modmul(W, S);
                    }
                    k += 2 * t;
                }
                t *= 2;
                m /= 2;
            }
            /* Last iteration merged with n^-1 */

            t = NewHope.DEGREE / 2;
            for (j = 0; j < t; j++) {
                U = x[j];
                V = x[j + t];
                W = U + NewHope.DEGREE * q - V;
                x[j + t] = this.modmul(W, NewHope.invpr);
                x[j] = this.modmul(U + V, NewHope.inv);
            }

            /* convert back from Montgomery to "normal" form */
            for (j = 0; j < NewHope.DEGREE; j++) {
                x[j] = this.redc(x[j]);
                x[j] -= q;
                x[j] += (x[j] >> (NewHope.WL - 1)) & q;
            }
        }
    };

    return NewHope;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports.NewHope = NewHope;
}

},{}],"./nhs":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* NewHope API high-level functions  */

var NHS = function(ctx) {
    "use strict";

    var NHS = {

        round: function(a, b) {
            return Math.floor((a + (b >> 1)) / b);
        },

        /* constant time absolute value */
        nabs: function(x) {
            var mask = (x >> 31);
            return (x + mask) ^ mask;
        },

        /* Montgomery stuff */

        redc: function(T) {
            var m = ((T & 0x3ffffff) * NHS.ND) & 0x3ffffff;
            return ((m * NHS.PRIME + T) * NHS.MODINV);
        },

        nres: function(x) {
            return NHS.redc(x * NHS.R2MODP);
        },

        modmul: function(a, b) {
            return NHS.redc(a * b);
        },

        /* NTT code */
        /* Cooley-Tukey NTT */

        ntt: function(x) {
            var t = NHS.DEGREE / 2,
                q = NHS.PRIME,
                m, i, j, k,
                S, U, V;

            /* Convert to Montgomery form */
            for (j = 0; j < NHS.DEGREE; j++) {
                x[j] = NHS.nres(x[j]);
            }

            m = 1;
            while (m < NHS.DEGREE) {
                k = 0;

                for (i = 0; i < m; i++) {
                    S = NHS.roots[m + i];

                    for (j = k; j < k + t; j++) {
                        U = x[j];
                        V = NHS.modmul(x[j + t], S);
                        x[j] = U + V;
                        x[j + t] = U + 2 * q - V;
                    }

                    k += 2 * t;
                }

                t /= 2;
                m *= 2;
            }
        },

        /* Gentleman-Sande INTT */
        intt: function(x) {
            var q = NHS.PRIME,
                t = 1,
                m, i, j, k,
                S, U, V, W;

            m = NHS.DEGREE / 2;
            while (m > 1) {
                k = 0;

                for (i = 0; i < m; i++) {
                    S = NHS.iroots[m + i];

                    for (j = k; j < k + t; j++) {
                        U = x[j];
                        V = x[j + t];
                        x[j] = U + V;
                        W = U + NHS.DEGREE * q - V;
                        x[j + t] = NHS.modmul(W, S);
                    }

                    k += 2 * t;
                }

                t *= 2;
                m /= 2;
            }
            /* Last iteration merged with n^-1 */

            t = NHS.DEGREE / 2;
            for (j = 0; j < t; j++) {
                U = x[j];
                V = x[j + t];
                W = U + NHS.DEGREE * q - V;
                x[j + t] = NHS.modmul(W, NHS.invpr);
                x[j] = NHS.modmul(U + V, NHS.inv);
            }

            /* convert back from Montgomery to "normal" form */
            for (j = 0; j < NHS.DEGREE; j++) {
                x[j] = NHS.redc(x[j]);
                x[j] -= q;
                x[j] += (x[j] >> (NHS.WL - 1)) & q;
            }
        },

        /* See https://eprint.iacr.org/2016/1157.pdf */

        Encode: function(key, poly) {
            var i, j, b, k, kj, q2;

            q2 = NHS.PRIME / 2;
            for (i = j = 0; i < 256;) {
                kj = key[j++];

                for (k = 0; k < 8; k++) {
                    b = kj & 1;
                    poly[i] = b * q2;
                    poly[i + 256] = b * q2;
                    poly[i + 512] = b * q2;
                    poly[i + 768] = b * q2;
                    kj >>= 1;
                    i++;
                }
            }
        },

        Decode: function(poly, key) {
            var q2 = NHS.PRIME / 2,
                i, j, k, b, t;

            for (i = 0; i < 32; i++) {
                key[i] = 0;
            }

            for (i = j = 0; i < 256;) {
                for (k = 0; k < 8; k++) {
                    t = NHS.nabs(poly[i] - q2) + NHS.nabs(poly[i + 256] - q2) + NHS.nabs(poly[i + 512] - q2) + NHS.nabs(poly[i + 768] - q2);

                    b = t - NHS.PRIME;
                    b = (b >> 31) & 1;
                    key[j] = (((key[j] & 0xff) >> 1) + (b << 7));
                    i++;
                }

                j++;
            }
        },

        /* convert 32-byte seed to random polynomial */

        Parse: function(seed, poly) {
            var sh = new ctx.SHA3(ctx.SHA3.SHAKE128),
                hash = [],
                i, j, n;

            for (i = 0; i < 32; i++) {
                sh.process(seed[i]);
            }
            sh.shake(hash, 4 * NHS.DEGREE);

            for (i = j = 0; i < NHS.DEGREE; i++) {
                n = hash[j] & 0x7f;
                n <<= 8;
                n += hash[j + 1] & 0xff;
                n <<= 8;
                n += hash[j + 2] & 0xff;
                n <<= 8;
                n += hash[j + 3] & 0xff;
                j += 4;
                poly[i] = NHS.modmul(n, NHS.ONE); // reduce 31-bit random number mod q
            }
        },

        /* Compress 14 bits polynomial coefficients into byte array */
        /* 7 bytes is 3x14 */
        pack: function(poly, array) {
            var i, j, a, b, c, d;

            for (i = j = 0; i < NHS.DEGREE;) {
                a = poly[i++];
                b = poly[i++];
                c = poly[i++];
                d = poly[i++];
                array[j++] = a & 0xff;
                array[j++] = ((a >> 8) | (b << 6)) & 0xff;
                array[j++] = (b >> 2) & 0xff;
                array[j++] = ((b >> 10) | (c << 4)) & 0xff;
                array[j++] = (c >> 4) & 0xff;
                array[j++] = ((c >> 12) | (d << 2)) & 0xff;
                array[j++] = (d >> 6);
            }
        },

        unpack: function(array, poly) {
            var i, j, a, b, c, d, e, f, g;

            for (i = j = 0; i < NHS.DEGREE;) {
                a = array[j++] & 0xff;
                b = array[j++] & 0xff;
                c = array[j++] & 0xff;
                d = array[j++] & 0xff;
                e = array[j++] & 0xff;
                f = array[j++] & 0xff;
                g = array[j++] & 0xff;
                poly[i++] = a | ((b & 0x3f) << 8);
                poly[i++] = (b >> 6) | (c << 2) | ((d & 0xf) << 10);
                poly[i++] = (d >> 4) | (e << 4) | ((f & 3) << 12);
                poly[i++] = (f >> 2) | (g << 6);
            }
        },


        /* See https://eprint.iacr.org/2016/1157.pdf */

        Compress: function(poly, array) {
            var col = 0,
                i, j, k, b;

            for (i = j = 0; i < NHS.DEGREE;) {
                for (k = 0; k < 8; k++) {
                    b = NHS.round((poly[i] * 8), NHS.PRIME) & 7;
                    col = (col << 3) + b;
                    i++;
                }

                array[j] = (col & 0xff);
                array[j + 1] = ((col >>> 8) & 0xff);
                array[j + 2] = ((col >>> 16) & 0xff);
                j += 3;
                col = 0;
            }
        },

        Decompress: function(array, poly) {
            var col = 0,
                i, j, k, b;

            for (i = j = 0; i < NHS.DEGREE;) {
                col = array[j + 2] & 0xff;
                col = (col << 8) + (array[j + 1] & 0xff);
                col = (col << 8) + (array[j] & 0xff);
                j += 3;

                for (k = 0; k < 8; k++) {
                    b = (col & 0xe00000) >>> 21;
                    col <<= 3;
                    poly[i] = NHS.round((b * NHS.PRIME), 8);
                    i++;
                }
            }
        },

        /* generate centered binomial distribution */

        Error: function(RNG, poly) {
            var n1, n2, r, i, j;

            for (i = 0; i < NHS.DEGREE; i++) {
                n1 = RNG.getByte() + (RNG.getByte() << 8);
                n2 = RNG.getByte() + (RNG.getByte() << 8);
                r = 0;

                for (j = 0; j < 16; j++) {
                    r += (n1 & 1) - (n2 & 1);
                    n1 >>= 1;
                    n2 >>= 1;
                }

                poly[i] = (r + NHS.PRIME);
            }
        },

        poly_mul: function(p1, p2, p3) {
            var i;

            for (i = 0; i < NHS.DEGREE; i++) {
                p1[i] = NHS.modmul(p2[i], p3[i]);
            }
        },

        poly_add: function(p1, p2, p3) {
            var i;

            for (i = 0; i < NHS.DEGREE; i++) {
                p1[i] = (p2[i] + p3[i]);
            }
        },

        poly_sub: function(p1, p2, p3) {
            var i;

            for (i = 0; i < NHS.DEGREE; i++) {
                p1[i] = (p2[i] + NHS.PRIME - p3[i]);
            }
        },

        /* reduces inputs < 2q */
        poly_soft_reduce: function(poly) {
            var i, e;

            for (i = 0; i < NHS.DEGREE; i++) {
                e = poly[i] - NHS.PRIME;
                poly[i] = e + ((e >> (NHS.WL - 1)) & NHS.PRIME);
            }
        },

        /* fully reduces modulo q */
        poly_hard_reduce: function(poly) {
            var i, e;

            for (i = 0; i < NHS.DEGREE; i++) {
                e = NHS.modmul(poly[i], NHS.ONE);
                e = e - NHS.PRIME;
                poly[i] = e + ((e >> (NHS.WL - 1)) & NHS.PRIME);
            }
        },

        bytestostring: function(b) {
            var s = "",
                len = b.length,
                ch, i;

            for (i = 0; i < len; i++) {
                ch = b[i];
                s += ((ch >>> 4) & 15).toString(16);
                s += (ch & 15).toString(16);
            }

            return s;
        },
        /* API files */

        SERVER_1: function(RNG, SB, S) {
            var seed = new Uint8Array(32),
                array = new Uint8Array(1792),
                s = new Int32Array(NHS.DEGREE),
                e = new Int32Array(NHS.DEGREE),
                b = new Int32Array(NHS.DEGREE),
                i;

            for (i = 0; i < 32; i++) {
                seed[i] = RNG.getByte();
            }

            NHS.Parse(seed, b);

            NHS.Error(RNG, e);
            NHS.Error(RNG, s);

            NHS.ntt(s);
            NHS.ntt(e);
            NHS.poly_mul(b, b, s);
            NHS.poly_add(b, b, e);
            NHS.poly_hard_reduce(b);

            NHS.pack(b, array);

            for (i = 0; i < 32; i++) {
                SB[i] = seed[i];
            }

            for (i = 0; i < 1792; i++) {
                SB[i + 32] = array[i];
            }

            NHS.poly_hard_reduce(s);

            NHS.pack(s, array);

            for (i = 0; i < 1792; i++) {
                S[i] = array[i];
            }
        },

        CLIENT: function(RNG, SB, UC, KEY) {
            var sh = new ctx.SHA3(ctx.SHA3.HASH256),
                seed = new Uint8Array(32),
                array = new Uint8Array(1792),
                key = new Uint8Array(32),
                cc = new Uint8Array(384),
                sd = new Int32Array(NHS.DEGREE),
                ed = new Int32Array(NHS.DEGREE),
                u = new Int32Array(NHS.DEGREE),
                k = new Int32Array(NHS.DEGREE),
                c = new Int32Array(NHS.DEGREE),
                i;

            NHS.Error(RNG, sd);
            NHS.Error(RNG, ed);

            NHS.ntt(sd);
            NHS.ntt(ed);

            for (i = 0; i < 32; i++) {
                seed[i] = SB[i];
            }

            for (i = 0; i < 1792; i++) {
                array[i] = SB[i + 32];
            }

            NHS.Parse(seed, u);

            NHS.poly_mul(u, u, sd);
            NHS.poly_add(u, u, ed);
            NHS.poly_hard_reduce(u);

            for (i = 0; i < 32; i++) {
                key[i] = RNG.getByte();
            }

            for (i = 0; i < 32; i++) {
                sh.process(key[i]);
            }

            sh.hash(key);

            NHS.Encode(key, k);

            NHS.unpack(array, c);

            NHS.poly_mul(c, c, sd);
            NHS.intt(c);
            NHS.Error(RNG, ed);
            NHS.poly_add(c, c, ed);
            NHS.poly_add(c, c, k);

            NHS.Compress(c, cc);

            sh.init(ctx.SHA3.HASH256);
            for (i = 0; i < 32; i++) {
                sh.process(key[i]);
            }
            sh.hash(key);

            for (i = 0; i < 32; i++) {
                KEY[i] = key[i];
            }

            NHS.pack(u, array);

            for (i = 0; i < 1792; i++) {
                UC[i] = array[i];
            }

            for (i = 0; i < 384; i++) {
                UC[i + 1792] = cc[i];
            }
        },

        SERVER_2: function(S, UC, KEY) {
            var sh = new ctx.SHA3(ctx.SHA3.HASH256),
                c = new Int32Array(NHS.DEGREE),
                s = new Int32Array(NHS.DEGREE),
                k = new Int32Array(NHS.DEGREE),
                array = new Uint8Array(1792),
                key = new Uint8Array(32),
                cc = new Uint8Array(384),
                i;

            for (i = 0; i < 1792; i++) {
                array[i] = UC[i];
            }

            NHS.unpack(array, k);

            for (i = 0; i < 384; i++) {
                cc[i] = UC[i + 1792];
            }

            NHS.Decompress(cc, c);

            for (i = 0; i < 1792; i++) {
                array[i] = S[i];
            }

            NHS.unpack(array, s);

            NHS.poly_mul(k, k, s);
            NHS.intt(k);
            NHS.poly_sub(k, c, k);
            NHS.poly_soft_reduce(k);

            NHS.Decode(k, key);

            for (i = 0; i < 32; i++) {
                sh.process(key[i]);
            }
            sh.hash(key);

            for (i = 0; i < 32; i++) {
                KEY[i] = key[i];
            }
        }

    };

    //q=12289
    NHS.PRIME = 0x3001; // q in Hex
    NHS.LGN = 10; // Degree n=2^LGN
    NHS.ND = 0x3002FFF; // 1/(R-q) mod R
    NHS.ONE = 0x2AAC; // R mod q
    NHS.R2MODP = 0x1DA2; // R^2 mod q

    NHS.MODINV = Math.pow(2, -26);

    NHS.DEGREE = 1024; // 1<< LGN
    NHS.WL = 26;

    NHS.inv = 0xffb;
    NHS.invpr = 0x1131;

    NHS.roots = [0x2aac, 0xd6f, 0x1c67, 0x2c5b, 0x2dbd, 0x2697, 0x29f6, 0x8d3, 0x1b7c, 0x9eb, 0x20eb, 0x264a, 0x27d0, 0x121b, 0x58c, 0x4d7, 0x17a2, 0x29eb, 0x1b72, 0x13b0, 0x19b1, 0x1581, 0x2ac9, 0x25e8, 0x249d, 0x2d5e, 0x363, 0x1f74, 0x1f8f, 0x20a4, 0x2cb2, 0x2d04, 0x1407, 0x2df9, 0x3ad, 0x23f7, 0x1a72, 0xa91, 0x37f, 0xdb3, 0x2315, 0x5e6, 0xa8f, 0x211d, 0xdad, 0x1f2b, 0x2e29, 0x26b0, 0x2009, 0x2fdd, 0x2881, 0x399, 0x586, 0x2781, 0x2ab5, 0x971, 0x234b, 0x1df3, 0x1d2a, 0x15dd, 0x1a6d, 0x2774, 0x7ff, 0x1ebe, 0x230, 0x1cf4, 0x180b, 0xb58, 0x198c, 0x2b40, 0x127b, 0x1d9d, 0x137f, 0xfa0, 0x144, 0x4b, 0x2fac, 0xb09, 0x1c7f, 0x1b5, 0xeec, 0xc58, 0x1248, 0x243c, 0x108a, 0x14b8, 0xe9, 0x2dfe, 0xfb, 0x2602, 0x2aec, 0x1bb7, 0x1098, 0x23d8, 0x783, 0x1b13, 0x2067, 0x20d6, 0x171c, 0x4, 0x662, 0x1097, 0x24b9, 0x1b9d, 0x27c4, 0x276e, 0x6bf, 0x757, 0x2e16, 0x472, 0x1d11, 0x1649, 0x2904, 0xed4, 0x6c5, 0x14ae, 0x2ef8, 0x2ae0, 0x2e7c, 0x2735, 0x1186, 0x4f2, 0x17bb, 0x297f, 0x1dc7, 0x1ae5, 0x2a43, 0x2c02, 0xed6, 0x2b70, 0x1c7b, 0x18d1, 0x20ae, 0x6ad, 0x2404, 0x113a, 0x209e, 0x31b, 0x159d, 0x48f, 0xe09, 0x1bb2, 0x14f7, 0x385, 0x1c4, 0x1cdb, 0x22d6, 0x21d8, 0xc, 0x1aae, 0x2ece, 0x2d81, 0xd56, 0x5c1, 0x12da, 0x8cf, 0x1605, 0x1bc4, 0x18b7, 0x19b9, 0x21be, 0x135e, 0x28d6, 0x2891, 0x2208, 0x17e1, 0x2971, 0x926, 0x211b, 0xff, 0x51f, 0xa85, 0xe1, 0x2c35, 0x2585, 0x121, 0xe27, 0x2e64, 0x29f8, 0x2d46, 0xcb2, 0x292a, 0x33d, 0xaf9, 0xb86, 0x2e3a, 0x2138, 0x1978, 0x2324, 0xf3f, 0x2d10, 0x1dfd, 0x13c3, 0x6cc, 0x1a79, 0x1221, 0x250f, 0xacd, 0xfff, 0x7b4, 0x650, 0x1893, 0xe85, 0x1f5d, 0x12dc, 0x2d42, 0xd8e, 0x1240, 0x1082, 0x12ef, 0x11b6, 0xfa8, 0xb0f, 0xdac, 0x191c, 0x1242, 0x1ea, 0x155, 0x270a, 0x9ed, 0x2e5b, 0x25d8, 0x222c, 0x7e9, 0x1fb3, 0x10ac, 0x2919, 0x2584, 0xbe3, 0x24fa, 0x23ed, 0x618, 0x2d80, 0x6fa, 0x140e, 0x588, 0x355, 0x1054, 0x26c4, 0x1e4f, 0x1681, 0x1f6f, 0x1c53, 0xfe4, 0xacb, 0x1680, 0x2fe8, 0x6c, 0x165a, 0x10bb, 0x2c39, 0x1804, 0x1196, 0x884, 0x2622, 0x629, 0x1ac1, 0x2232, 0x2f9b, 0xd3e, 0x20ff, 0x12c0, 0x27ec, 0x5a, 0x2a0, 0x5f1, 0x1cda, 0x403, 0x1ea8, 0x1719, 0x1fc7, 0x2d23, 0x5ea, 0x25d1, 0xb6, 0x49c, 0xac7, 0x2d9c, 0x204e, 0x2142, 0x11e8, 0xed0, 0x15f0, 0x514, 0xa3f, 0xf43, 0x1de5, 0x2d97, 0x1543, 0x2c7b, 0x241a, 0x2223, 0x2fb8, 0x25b7, 0x1b4c, 0x2f36, 0x26e2, 0x100, 0x2555, 0x266c, 0x2e10, 0x271c, 0x5aa, 0x1789, 0x2199, 0x291d, 0x1088, 0x2046, 0x1ea1, 0xf89, 0x1c7a, 0x1e98, 0x137, 0x1b65, 0x24ed, 0xf37, 0x2ec3, 0xd0c, 0x7c7, 0x123f, 0xb2e, 0x1a97, 0x1a03, 0x1bcd, 0x3b2, 0x714, 0x2979, 0xaef, 0x2b3c, 0x2d91, 0xe03, 0xe5b, 0x1fbc, 0xcae, 0x432, 0x23a4, 0xb1d, 0x1ccc, 0x1fb6, 0x2f58, 0x2a5a, 0x723, 0x2c99, 0x2d70, 0xa, 0x263c, 0x2701, 0xdeb, 0x2d08, 0x1c34, 0x200c, 0x1e88, 0x396, 0x18d5, 0x1c45, 0xc4, 0x18bc, 0x2cd7, 0x1744, 0x8f1, 0x1c5c, 0xbe6, 0x2a89, 0x17a0, 0x207, 0x19ce, 0x2024, 0x23e3, 0x299b, 0x685, 0x2baf, 0x539, 0x2d49, 0x24b5, 0x158d, 0xfd, 0x2a95, 0x24d, 0xab3, 0x1125, 0x12f9, 0x15ba, 0x6a8, 0x2c36, 0x6e7, 0x1044, 0x36e, 0xfe8, 0x112d, 0x2717, 0x24a0, 0x1c09, 0xe1d, 0x828, 0x2f7, 0x1f5b, 0xfab, 0xcf6, 0x1332, 0x1c72, 0x2683, 0x15ce, 0x1ad3, 0x1a36, 0x24c, 0xb33, 0x253f, 0x1583, 0x1d69, 0x29ec, 0xba7, 0x2f97, 0x16df, 0x1068, 0xaee, 0xc4f, 0x153c, 0x24eb, 0x20cd, 0x1398, 0x2366, 0x11f9, 0xe77, 0x103d, 0x260a, 0xce, 0xaea, 0x236b, 0x2b11, 0x5f8, 0xe4f, 0x750, 0x1569, 0x10f5, 0x284e, 0xa38, 0x2e06, 0xe0, 0xeaa, 0x99e, 0x249b, 0x8eb, 0x2b97, 0x2fdf, 0x29c1, 0x1b00, 0x2fe3, 0x1d4f, 0x83f, 0x2d06, 0x10e, 0x183f, 0x27ba, 0x132, 0xfbf, 0x296d, 0x154a, 0x40a, 0x2767, 0xad, 0xc09, 0x974, 0x2821, 0x1e2e, 0x28d2, 0xfac, 0x3c4, 0x2f19, 0xdd4, 0x2ddf, 0x1e43, 0x1e90, 0x2dc9, 0x1144, 0x28c3, 0x653, 0xf3c, 0x1e32, 0x2a4a, 0x391, 0x1123, 0xdb, 0x2da0, 0xe1e, 0x667, 0x23b5, 0x2039, 0xa92, 0x1552, 0x5d3, 0x169a, 0x1f03, 0x1342, 0x2004, 0x1b5d, 0x2d01, 0x2e9b, 0x41f, 0x2bc7, 0xa94, 0xd0, 0x2e6a, 0x2b38, 0x14ac, 0x2724, 0x3ba, 0x6bc, 0x18ac, 0x2da5, 0x213c, 0x2c5c, 0xdd3, 0xaae, 0x2e08, 0x6cd, 0x1677, 0x2025, 0x1e1c, 0x5b4, 0xdc4, 0x60, 0x156c, 0x2669, 0x1c01, 0x26ab, 0x1ebb, 0x26d4, 0x21e1, 0x156b, 0x567, 0x1a, 0x29ce, 0x23d4, 0x684, 0xb79, 0x1953, 0x1046, 0x1d8c, 0x17b5, 0x1c28, 0x1ce5, 0x2478, 0x18d8, 0x1b16, 0x2c2f, 0x21c9, 0x19bb, 0xbbc, 0x291b, 0x19f6, 0x1879, 0x2fe4, 0x58e, 0x294a, 0x19e8, 0x27c7, 0x2fba, 0x1a29, 0x2319, 0x1ecb, 0x203b, 0x2f05, 0x2b82, 0x192f, 0x26aa, 0x2482, 0xaed, 0x1216, 0x708, 0x11a1, 0xc22, 0x908, 0x28f8, 0x2427, 0x7f8, 0x172e, 0xf50, 0xaa8, 0x184a, 0x1f67, 0x22d1, 0xeba, 0x215b, 0xf47, 0x2877, 0xd5e, 0x8dc, 0x20d, 0x2dae, 0x1d3e, 0x775, 0xbf3, 0x872, 0x2667, 0x1ff6, 0xd9f, 0x13c4, 0x105, 0x65f, 0x21ec, 0x6dd, 0x1a09, 0xc6e, 0x1fd, 0x1426, 0xae3, 0x494, 0x2d82, 0x22cd, 0x25d6, 0x11c1, 0x1c, 0x2cae, 0x141f, 0x110a, 0x147, 0x2657, 0x23fd, 0x2f39, 0x360, 0x2294, 0x1f1e, 0xb73, 0xbfc, 0x2f17, 0x7ca, 0x2f63, 0xbf, 0x28c2, 0xc1a, 0x255e, 0x226e, 0x1aa8, 0x229e, 0x161a, 0x273, 0x106d, 0x2c40, 0x7cf, 0x1408, 0x7d8, 0x100a, 0x759, 0x1db4, 0x24be, 0x2ebb, 0xc17, 0x1894, 0x244e, 0x15bd, 0x748, 0x1fe9, 0x23d, 0x1da, 0x2be, 0x18a3, 0xc5c, 0x9f9, 0x3d5, 0x2ce4, 0x54, 0x2abf, 0x279c, 0x1e81, 0x2d59, 0x2847, 0x23f4, 0xda8, 0xa20, 0x258, 0x1cfe, 0x240c, 0x2c2e, 0x2790, 0x2dd5, 0x2bf2, 0x2e34, 0x1724, 0x211, 0x1009, 0x27b9, 0x6f9, 0x23d9, 0x19a2, 0x627, 0x156d, 0x169e, 0x7e7, 0x30f, 0x24b6, 0x5c2, 0x1ce4, 0x28dd, 0x20, 0x16ab, 0x1cce, 0x20a9, 0x2390, 0x2884, 0x2245, 0x5f7, 0xab7, 0x1b6a, 0x11e7, 0x2a53, 0x2f94, 0x294c, 0x1ee5, 0x1364, 0x1b9a, 0xff7, 0x5eb, 0x2c30, 0x1c02, 0x5a1, 0x1b87, 0x2402, 0x1cc8, 0x2ee1, 0x1fbe, 0x138c, 0x2487, 0x1bf8, 0xd96, 0x1d68, 0x2fb3, 0x1fc1, 0x1fcc, 0xd66, 0x953, 0x2141, 0x157a, 0x2477, 0x18e3, 0x2f30, 0x75e, 0x1de1, 0x14b2, 0x2faa, 0x1697, 0x2334, 0x12d1, 0xb76, 0x2aa8, 0x1e7a, 0xd5, 0x2c60, 0x26b8, 0x1753, 0x124a, 0x1f57, 0x1425, 0xd84, 0x1c05, 0x641, 0xf3a, 0x1b8c, 0xd7d, 0x2f52, 0x2f4, 0xc73, 0x151b, 0x1589, 0x1819, 0x1b18, 0xb9b, 0x1ae9, 0x2b1f, 0x2b44, 0x2f5a, 0x2d37, 0x2cb1, 0x26f5, 0x233e, 0x276f, 0x276, 0x1260, 0x2997, 0x9f2, 0x1c15, 0x1694, 0x11ac, 0x1e6d, 0x1bef, 0x2966, 0x18b2, 0x4fa, 0x2044, 0x1b70, 0x1f3e, 0x221e, 0x28ca, 0x1d56, 0x7ae, 0x98d, 0x238c, 0x17b8, 0xad3, 0x113f, 0x1f1b, 0x4d2, 0x1757, 0xcb1, 0x2ef1, 0x2e02, 0x17fc, 0x2f11, 0x2a74, 0x2029, 0x700, 0x154e, 0x1cef, 0x226a, 0x21bf, 0x27a6, 0x14bc, 0x2b2b, 0x2fc6, 0x13b6, 0x21e6, 0x1663, 0xcbd, 0x752, 0x1624, 0x881, 0x2fc0, 0x1276, 0xa7f, 0x274f, 0x2b53, 0x670, 0x1fb7, 0x1e41, 0x2a1e, 0x2612, 0x297, 0x19de, 0x18b, 0x249, 0x1c88, 0xe9e, 0x1ef1, 0x213, 0x47b, 0x1e20, 0x28c1, 0x1d5e, 0x977, 0x1dca, 0x990, 0x1df6, 0x2b62, 0x870, 0x1f4, 0x1829, 0x1e0a, 0x46, 0x1b9f, 0x2102, 0x16b, 0x1b32, 0x568, 0x2050, 0x15b4, 0x191a, 0x1dd0, 0x5df, 0x55c, 0x1d21, 0x19db, 0x12d9, 0xe96, 0x680, 0x2349, 0x9b9, 0x155d, 0xe31, 0x249f, 0x20f8, 0xb30, 0x337, 0x2da3, 0x11c3, 0x248f, 0x1cf9, 0x10ee, 0x6d8, 0x6eb, 0xa0d, 0x101b, 0x1ae4, 0x1801, 0x24cd, 0x813, 0x2e98, 0x1574, 0x50, 0x11da, 0x1802, 0xf56, 0x1839, 0x219c, 0x105b, 0x43b, 0x2c9, 0x917, 0x14c1, 0x1b79, 0xdab, 0x2ab9, 0x265c, 0x71a, 0x1d90, 0x89f, 0x2bc2, 0x2777, 0x1014, 0x1e64, 0x14b4, 0x692, 0xddb, 0x56e, 0x2190, 0x2d1b, 0x1016, 0x12d6, 0x1c81, 0x2628, 0x4a1, 0x1268, 0x2597, 0x2926, 0x7c5, 0x1dcd, 0x53f, 0x11a9, 0x1a41, 0x5a2, 0x1c65, 0x7e8, 0xd71, 0x29c8, 0x427, 0x32f, 0x5dc, 0x16b1, 0x2a1d, 0x1787, 0x2224, 0x620, 0x6a4, 0x1351, 0x1038, 0xe6c, 0x111b, 0x2f13, 0x441, 0x2cfd, 0x2f2f, 0xd25, 0x9b8, 0x1b24, 0x762, 0x19b6, 0x2611, 0x85e, 0xe37, 0x1f5, 0x503, 0x1c46, 0x23cc, 0x4bb, 0x243e, 0x122b, 0x28e2, 0x133e, 0x2db9, 0xdb2, 0x1a5c, 0x29a9, 0xca, 0x2113, 0x13d1, 0x15ec, 0x2079, 0x18da, 0x2d50, 0x2c45, 0xaa2, 0x135a, 0x800, 0x18f7, 0x17f3, 0x5fd, 0x1f5a, 0x2d0, 0x2cd1, 0x9ee, 0x218b, 0x19fd, 0x53b, 0x28c5, 0xe33, 0x1911, 0x26cc, 0x2018, 0x2f88, 0x1b01, 0x2637, 0x1cd9, 0x126b, 0x1a0b, 0x5b0, 0x24e0, 0xe82, 0xb1, 0x21f7, 0x1a16, 0x2f24, 0x1cb1, 0x1f7d, 0x28a0, 0x167e, 0xc3];
    NHS.iroots = [0x2aac, 0x2292, 0x3a6, 0x139a, 0x272e, 0x60b, 0x96a, 0x244, 0x2b2a, 0x2a75, 0x1de6, 0x831, 0x9b7, 0xf16, 0x2616, 0x1485, 0x2fd, 0x34f, 0xf5d, 0x1072, 0x108d, 0x2c9e, 0x2a3, 0xb64, 0xa19, 0x538, 0x1a80, 0x1650, 0x1c51, 0x148f, 0x616, 0x185f, 0x1143, 0x2802, 0x88d, 0x1594, 0x1a24, 0x12d7, 0x120e, 0xcb6, 0x2690, 0x54c, 0x880, 0x2a7b, 0x2c68, 0x780, 0x24, 0xff8, 0x951, 0x1d8, 0x10d6, 0x2254, 0xee4, 0x2572, 0x2a1b, 0xcec, 0x224e, 0x2c82, 0x2570, 0x158f, 0xc0a, 0x2c54, 0x208, 0x1bfa, 0x3ff, 0x5be, 0x151c, 0x123a, 0x682, 0x1846, 0x2b0f, 0x1e7b, 0x8cc, 0x185, 0x521, 0x109, 0x1b53, 0x293c, 0x212d, 0x6fd, 0x19b8, 0x12f0, 0x2b8f, 0x1eb, 0x28aa, 0x2942, 0x893, 0x83d, 0x1464, 0xb48, 0x1f6a, 0x299f, 0x2ffd, 0x18e5, 0xf2b, 0xf9a, 0x14ee, 0x287e, 0xc29, 0x1f69, 0x144a, 0x515, 0x9ff, 0x2f06, 0x203, 0x2f18, 0x1b49, 0x1f77, 0xbc5, 0x1db9, 0x23a9, 0x2115, 0x2e4c, 0x1382, 0x24f8, 0x55, 0x2fb6, 0x2ebd, 0x2061, 0x1c82, 0x1264, 0x1d86, 0x4c1, 0x1675, 0x24a9, 0x17f6, 0x130d, 0x2dd1, 0x29d8, 0x9df, 0x277d, 0x1e6b, 0x17fd, 0x3c8, 0x1f46, 0x19a7, 0x2f95, 0x19, 0x1981, 0x2536, 0x201d, 0x13ae, 0x1092, 0x1980, 0x11b2, 0x93d, 0x1fad, 0x2cac, 0x2a79, 0x1bf3, 0x2907, 0x281, 0x29e9, 0xc14, 0xb07, 0x241e, 0xa7d, 0x6e8, 0x1f55, 0x104e, 0x2818, 0xdd5, 0xa29, 0x1a6, 0x2614, 0x8f7, 0x2eac, 0x2e17, 0x1dbf, 0x16e5, 0x2255, 0x24f2, 0x2059, 0x1e4b, 0x1d12, 0x1f7f, 0x1dc1, 0x2273, 0x2bf, 0x1d25, 0x10a4, 0x217c, 0x176e, 0x29b1, 0x284d, 0x2002, 0x2534, 0xaf2, 0x1de0, 0x1588, 0x2935, 0x1c3e, 0x1204, 0x2f1, 0x20c2, 0xcdd, 0x1689, 0xec9, 0x1c7, 0x247b, 0x2508, 0x2cc4, 0x6d7, 0x234f, 0x2bb, 0x609, 0x19d, 0x21da, 0x2ee0, 0xa7c, 0x3cc, 0x2f20, 0x257c, 0x2ae2, 0x2f02, 0xee6, 0x26db, 0x690, 0x1820, 0xdf9, 0x770, 0x72b, 0x1ca3, 0xe43, 0x1648, 0x174a, 0x143d, 0x19fc, 0x2732, 0x1d27, 0x2a40, 0x22ab, 0x280, 0x133, 0x1553, 0x2ff5, 0xe29, 0xd2b, 0x1326, 0x2e3d, 0x2c7c, 0x1b0a, 0x144f, 0x21f8, 0x2b72, 0x1a64, 0x2ce6, 0xf63, 0x1ec7, 0xbfd, 0x2954, 0xf53, 0x1730, 0x1386, 0x491, 0x212b, 0x222e, 0x3a5, 0xec5, 0x25c, 0x1755, 0x2945, 0x2c47, 0x8dd, 0x1b55, 0x4c9, 0x197, 0x2f31, 0x256d, 0x43a, 0x2be2, 0x166, 0x300, 0x14a4, 0xffd, 0x1cbf, 0x10fe, 0x1967, 0x2a2e, 0x1aaf, 0x256f, 0xfc8, 0xc4c, 0x299a, 0x21e3, 0x261, 0x2f26, 0x1ede, 0x2c70, 0x5b7, 0x11cf, 0x20c5, 0x29ae, 0x73e, 0x1ebd, 0x238, 0x1171, 0x11be, 0x222, 0x222d, 0xe8, 0x2c3d, 0x2055, 0x72f, 0x11d3, 0x7e0, 0x268d, 0x23f8, 0x2f54, 0x89a, 0x2bf7, 0x1ab7, 0x694, 0x2042, 0x2ecf, 0x847, 0x17c2, 0x2ef3, 0x2fb, 0x27c2, 0x12b2, 0x1e, 0x1501, 0x640, 0x22, 0x46a, 0x2716, 0xb66, 0x2663, 0x2157, 0x2f21, 0x1fb, 0x25c9, 0x7b3, 0x1f0c, 0x1a98, 0x28b1, 0x21b2, 0x2a09, 0x4f0, 0xc96, 0x2517, 0x2f33, 0x9f7, 0x1fc4, 0x218a, 0x1e08, 0xc9b, 0x1c69, 0xf34, 0xb16, 0x1ac5, 0x23b2, 0x2513, 0x1f99, 0x1922, 0x6a, 0x245a, 0x615, 0x1298, 0x1a7e, 0xac2, 0x24ce, 0x2db5, 0x15cb, 0x152e, 0x1a33, 0x97e, 0x138f, 0x1ccf, 0x230b, 0x2056, 0x10a6, 0x2d0a, 0x27d9, 0x21e4, 0x13f8, 0xb61, 0x8ea, 0x1ed4, 0x2019, 0x2c93, 0x1fbd, 0x291a, 0x3cb, 0x2959, 0x1a47, 0x1d08, 0x1edc, 0x254e, 0x2db4, 0x56c, 0x2f04, 0x1a74, 0xb4c, 0x2b8, 0x2ac8, 0x452, 0x297c, 0x666, 0xc1e, 0xfdd, 0x1633, 0x2dfa, 0x1861, 0x578, 0x241b, 0x13a5, 0x2710, 0x18bd, 0x32a, 0x1745, 0x2f3d, 0x13bc, 0x172c, 0x2c6b, 0x1179, 0xff5, 0x13cd, 0x2f9, 0x2216, 0x900, 0x9c5, 0x2ff7, 0x291, 0x368, 0x28de, 0x5a7, 0xa9, 0x104b, 0x1335, 0x24e4, 0xc5d, 0x2bcf, 0x2353, 0x1045, 0x21a6, 0x21fe, 0x270, 0x4c5, 0x2512, 0x688, 0x28ed, 0x2c4f, 0x1434, 0x15fe, 0x156a, 0x24d3, 0x1dc2, 0x283a, 0x22f5, 0x13e, 0x20ca, 0xb14, 0x149c, 0x2eca, 0x1169, 0x1387, 0x2078, 0x1160, 0xfbb, 0x1f79, 0x6e4, 0xe68, 0x1878, 0x2a57, 0x8e5, 0x1f1, 0x995, 0xaac, 0x2f01, 0x91f, 0xcb, 0x14b5, 0xa4a, 0x49, 0xdde, 0xbe7, 0x386, 0x1abe, 0x26a, 0x121c, 0x20be, 0x25c2, 0x2aed, 0x1a11, 0x2131, 0x1e19, 0xebf, 0xfb3, 0x265, 0x253a, 0x2b65, 0x2f4b, 0xa30, 0x2a17, 0x2de, 0x103a, 0x18e8, 0x1159, 0x2bfe, 0x1327, 0x2a10, 0x2d61, 0x2fa7, 0x815, 0x1d41, 0xf02, 0x22c3, 0x66, 0xdcf, 0x1540, 0x2f3e, 0x1983, 0x761, 0x1084, 0x1350, 0xdd, 0x15eb, 0xe0a, 0x2f50, 0x217f, 0xb21, 0x2a51, 0x15f6, 0x1d96, 0x1328, 0x9ca, 0x1500, 0x79, 0xfe9, 0x935, 0x16f0, 0x21ce, 0x73c, 0x2ac6, 0x1604, 0xe76, 0x2613, 0x330, 0x2d31, 0x10a7, 0x2a04, 0x180e, 0x170a, 0x2801, 0x1ca7, 0x255f, 0x3bc, 0x2b1, 0x1727, 0xf88, 0x1a15, 0x1c30, 0xeee, 0x2f37, 0x658, 0x15a5, 0x224f, 0x248, 0x1cc3, 0x71f, 0x1dd6, 0xbc3, 0x2b46, 0xc35, 0x13bb, 0x2afe, 0x2e0c, 0x21ca, 0x27a3, 0x9f0, 0x164b, 0x289f, 0x14dd, 0x2649, 0x22dc, 0xd2, 0x304, 0x2bc0, 0xee, 0x1ee6, 0x2195, 0x1fc9, 0x1cb0, 0x295d, 0x29e1, 0xddd, 0x187a, 0x5e4, 0x1950, 0x2a25, 0x2cd2, 0x2bda, 0x639, 0x2290, 0x2819, 0x139c, 0x2a5f, 0x15c0, 0x1e58, 0x2ac2, 0x1234, 0x283c, 0x6db, 0xa6a, 0x1d99, 0x2b60, 0x9d9, 0x1380, 0x1d2b, 0x1feb, 0x2e6, 0xe71, 0x2a93, 0x2226, 0x296f, 0x1b4d, 0x119d, 0x1fed, 0x88a, 0x43f, 0x2762, 0x1271, 0x28e7, 0x9a5, 0x548, 0x2256, 0x1488, 0x1b40, 0x26ea, 0x2d38, 0x2bc6, 0x1fa6, 0xe65, 0x17c8, 0x20ab, 0x17ff, 0x1e27, 0x2fb1, 0x1a8d, 0x169, 0x27ee, 0xb34, 0x1800, 0x151d, 0x1fe6, 0x25f4, 0x2916, 0x2929, 0x1f13, 0x1308, 0xb72, 0x1e3e, 0x25e, 0x2cca, 0x24d1, 0xf09, 0xb62, 0x21d0, 0x1aa4, 0x2648, 0xcb8, 0x2981, 0x216b, 0x1d28, 0x1626, 0x12e0, 0x2aa5, 0x2a22, 0x1231, 0x16e7, 0x1a4d, 0xfb1, 0x2a99, 0x14cf, 0x2e96, 0xeff, 0x1462, 0x2fbb, 0x11f7, 0x17d8, 0x2e0d, 0x2791, 0x49f, 0x120b, 0x2671, 0x1237, 0x268a, 0x12a3, 0x740, 0x11e1, 0x2b86, 0x2dee, 0x1110, 0x2163, 0x1379, 0x2db8, 0x2e76, 0x1623, 0x2d6a, 0x9ef, 0x5e3, 0x11c0, 0x104a, 0x2991, 0x4ae, 0x8b2, 0x2582, 0x1d8b, 0x41, 0x2780, 0x19dd, 0x28af, 0x2344, 0x199e, 0xe1b, 0x1c4b, 0x3b, 0x4d6, 0x1b45, 0x85b, 0xe42, 0xd97, 0x1312, 0x1ab3, 0x2901, 0xfd8, 0x58d, 0xf0, 0x1805, 0x1ff, 0x110, 0x2350, 0x18aa, 0x2b2f, 0x10e6, 0x1ec2, 0x252e, 0x1849, 0xc75, 0x2674, 0x2853, 0x12ab, 0x737, 0xde3, 0x10c3, 0x1491, 0xfbd, 0x2b07, 0x174f, 0x69b, 0x1412, 0x1194, 0x1e55, 0x196d, 0x13ec, 0x260f, 0x66a, 0x1da1, 0x2d8b, 0x892, 0xcc3, 0x90c, 0x350, 0x2ca, 0xa7, 0x4bd, 0x4e2, 0x1518, 0x2466, 0x14e9, 0x17e8, 0x1a78, 0x1ae6, 0x238e, 0x2d0d, 0xaf, 0x2284, 0x1475, 0x20c7, 0x29c0, 0x13fc, 0x227d, 0x1bdc, 0x10aa, 0x1db7, 0x18ae, 0x949, 0x3a1, 0x2f2c, 0x1187, 0x559, 0x248b, 0x1d30, 0xccd, 0x196a, 0x57, 0x1b4f, 0x1220, 0x28a3, 0xd1, 0x171e, 0xb8a, 0x1a87, 0xec0, 0x26ae, 0x229b, 0x1035, 0x1040, 0x4e, 0x1299, 0x226b, 0x1409, 0xb7a, 0x1c75, 0x1043, 0x120, 0x1339, 0xbff, 0x147a, 0x2a60, 0x13ff, 0x3d1, 0x2a16, 0x200a, 0x1467, 0x1c9d, 0x111c, 0x6b5, 0x6d, 0x5ae, 0x1e1a, 0x1497, 0x254a, 0x2a0a, 0xdbc, 0x77d, 0xc71, 0xf58, 0x1333, 0x1956, 0x2fe1, 0x724, 0x131d, 0x2a3f, 0xb4b, 0x2cf2, 0x281a, 0x1963, 0x1a94, 0x29da, 0x165f, 0xc28, 0x2908, 0x848, 0x1ff8, 0x2df0, 0x18dd, 0x1cd, 0x40f, 0x22c, 0x871, 0x3d3, 0xbf5, 0x1303, 0x2da9, 0x25e1, 0x2259, 0xc0d, 0x7ba, 0x2a8, 0x1180, 0x865, 0x542, 0x2fad, 0x31d, 0x2c2c, 0x2608, 0x23a5, 0x175e, 0x2d43, 0x2e27, 0x2dc4, 0x1018, 0x28b9, 0x1a44, 0xbb3, 0x176d, 0x23ea, 0x146, 0xb43, 0x124d, 0x28a8, 0x1ff7, 0x2829, 0x1bf9, 0x2832, 0x3c1, 0x1f94, 0x2d8e, 0x19e7, 0xd63, 0x1559, 0xd93, 0xaa3, 0x23e7, 0x73f, 0x2f42, 0x9e, 0x2837, 0xea, 0x2405, 0x248e, 0x10e3, 0xd6d, 0x2ca1, 0xc8, 0xc04, 0x9aa, 0x2eba, 0x1ef7, 0x1be2, 0x353, 0x2fe5, 0x1e40, 0xa2b, 0xd34, 0x27f, 0x2b6d, 0x251e, 0x1bdb, 0x2e04, 0x2393, 0x15f8, 0x2924, 0xe15, 0x29a2, 0x2efc, 0x1c3d, 0x2262, 0x100b, 0x99a, 0x278f, 0x240e, 0x288c, 0x12c3, 0x253, 0x2df4, 0x2725, 0x22a3, 0x78a, 0x20ba, 0xea6, 0x2147, 0xd30, 0x109a, 0x17b7, 0x2559, 0x20b1, 0x18d3, 0x2809, 0xbda, 0x709, 0x26f9, 0x23df, 0x1e60, 0x28f9, 0x1deb, 0x2514, 0xb7f, 0x957, 0x16d2, 0x47f, 0xfc, 0xfc6, 0x1136, 0xce8, 0x15d8, 0x47, 0x83a, 0x1619, 0x6b7, 0x2a73, 0x1d, 0x1788, 0x160b, 0x6e6, 0x2445, 0x1646, 0xe38, 0x3d2, 0x14eb, 0x1729, 0xb89, 0x131c, 0x13d9, 0x184c, 0x1275, 0x1fbb, 0x16ae, 0x2488, 0x297d, 0xc2d, 0x633, 0x2fe7, 0x2a9a, 0x1a96, 0xe20, 0x92d, 0x1146, 0x956, 0x1400, 0x998, 0x1a95, 0x2fa1, 0x223d, 0x2a4d, 0x11e5, 0xfdc, 0x198a, 0x2934, 0x1f9, 0x2553];

    return NHS;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports.NHS = NHS;
}

},{}],"./pair":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

var PAIR = function(ctx) {
    "use strict";

    var PAIR = {
        /* Line function */
        line: function(A, B, Qx, Qy) {
            var r = new ctx.FP12(1),
                c = new ctx.FP4(0),
                XX, YY, ZZ, YZ, sb,
                X1, Y1, T1, T2,
                a, b;

            if (A == B) { /* Doubling */
                XX = new ctx.FP2(A.getx());
                YY = new ctx.FP2(A.gety());
                ZZ = new ctx.FP2(A.getz());
                YZ = new ctx.FP2(YY);

                YZ.mul(ZZ); //YZ
                XX.sqr(); //X^2
                YY.sqr(); //Y^2
                ZZ.sqr(); //Z^2

                YZ.imul(4);
                YZ.neg();
                YZ.norm(); //-2YZ
                YZ.pmul(Qy); //-2YZ.Ys

                XX.imul(6); //3X^2
                XX.pmul(Qx); //3X^2.Xs

                sb = 3 * ctx.ROM_CURVE.CURVE_B_I;
                ZZ.imul(sb);
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                    ZZ.div_ip2();
                }
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                    ZZ.mul_ip();
                    ZZ.add(ZZ);
                    YZ.mul_ip();
                    YZ.norm();
                }
                ZZ.norm(); // 3b.Z^2

                YY.add(YY);
                ZZ.sub(YY);
                ZZ.norm(); // 3b.Z^2-Y^2

                a = new ctx.FP4(YZ, ZZ); // -2YZ.Ys | 3b.Z^2-Y^2 | 3X^2.Xs
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                    b = new ctx.FP4(XX); // L(0,1) | L(0,0) | L(1,0)
                    c = new ctx.FP4(0);
                }
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                    b = new ctx.FP4(0);
                    c = new ctx.FP4(XX); c.times_i();
                }

                A.dbl();
            } else { /* Addition */
                X1 = new ctx.FP2(A.getx()); // X1
                Y1 = new ctx.FP2(A.gety()); // Y1
                T1 = new ctx.FP2(A.getz()); // Z1
                T2 = new ctx.FP2(A.getz()); // Z1

                T1.mul(B.gety()); // T1=Z1.Y2
                T2.mul(B.getx()); // T2=Z1.X2

                X1.sub(T2);
                X1.norm(); // X1=X1-Z1.X2
                Y1.sub(T1);
                Y1.norm(); // Y1=Y1-Z1.Y2

                T1.copy(X1); // T1=X1-Z1.X2
                X1.pmul(Qy); // X1=(X1-Z1.X2).Ys

                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                    X1.mul_ip();
                    X1.norm();
                }

                T1.mul(B.gety()); // T1=(X1-Z1.X2).Y2

                T2.copy(Y1); // T2=Y1-Z1.Y2
                T2.mul(B.getx()); // T2=(Y1-Z1.Y2).X2
                T2.sub(T1);
                T2.norm(); // T2=(Y1-Z1.Y2).X2 - (X1-Z1.X2).Y2
                Y1.pmul(Qx);
                Y1.neg();
                Y1.norm(); // Y1=-(Y1-Z1.Y2).Xs

                a = new ctx.FP4(X1, T2); // (X1-Z1.X2).Ys  |  (Y1-Z1.Y2).X2 - (X1-Z1.X2).Y2  | - (Y1-Z1.Y2).Xs
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.D_TYPE) {
                    b = new ctx.FP4(Y1);
                    c = new ctx.FP4(0);
                }
                if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                    b = new ctx.FP4(0);
                    c = new ctx.FP4(Y1); c.times_i();
                }

                A.add(B);
            }

            r.set(a, b, c);

            return r;
        },

        /* Optimal R-ate pairing */
        ate: function(P, Q) {
            var fa, fb, f, x, n, n3, K, lv,
                Qx, Qy, A, r, nb,
                i;

            fa = new ctx.BIG(0);
            fa.rcopy(ctx.ROM_FIELD.Fra);
            fb = new ctx.BIG(0);
            fb.rcopy(ctx.ROM_FIELD.Frb);
            f = new ctx.FP2(fa, fb); //f.bset(fa,fb);

            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                f.inverse();
                f.norm();
            }

            x = new ctx.BIG(0);
            x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);
            n = new ctx.BIG(x); //n.copy(x);
            K = new ctx.ECP2();

            if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BN) {
                n.pmul(6);
                if (ctx.ECP.SIGN_OF_X == ctx.ECP.POSITIVEX) {
                    n.inc(2)
                } else {
                    n.dec(2);
                }
            } else {
                n.copy(x);
            }
            n.norm();

            n3 = new ctx.BIG(n);
            n3.pmul(3);
            n3.norm();

            //  P.affine();
            //  Q.affine();
            Qx = new ctx.FP(Q.getx()); //Qx.copy(Q.getx());
            Qy = new ctx.FP(Q.gety()); //Qy.copy(Q.gety());

            A = new ctx.ECP2();
            r = new ctx.FP12(1);

            A.copy(P);
            nb = n3.nbits();

            for (var i = nb - 2; i >= 1; i--) {
                r.sqr();
                lv = PAIR.line(A, A, Qx, Qy);

                r.smul(lv,ctx.ECP.SEXTIC_TWIST);

                var bt=n3.bit(i)-n.bit(i);

                if (bt == 1) {
                    lv = PAIR.line(A, P, Qx, Qy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                }
                if (bt == -1) {
                    P.neg();
                    lv = PAIR.line(A, P, Qx, Qy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                    P.neg();
                }
            }

            /* R-ate fixup */
            if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BN) {
                if (ctx.ECP.SIGN_OF_X == ctx.ECP.NEGATIVEX) {
                    r.conj();
                    A.neg();
                }

                K.copy(P);
                K.frob(f);

                lv = PAIR.line(A, K, Qx, Qy);
                r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                K.frob(f);
                K.neg();
                lv = PAIR.line(A, K, Qx, Qy);
                r.smul(lv,ctx.ECP.SEXTIC_TWIST);
            }

            return r;
        },

        /* Optimal R-ate double pairing e(P,Q).e(R,S) */
        ate2: function(P, Q, R, S) {
            var fa, fb, f, x, n, n3, K, lv,
                Qx, Qy, Sx, Sy, A, B, r, nb, bt,
                i;

            fa = new ctx.BIG(0);
            fa.rcopy(ctx.ROM_FIELD.Fra);
            fb = new ctx.BIG(0);
            fb.rcopy(ctx.ROM_FIELD.Frb);
            f = new ctx.FP2(fa, fb); //f.bset(fa,fb);

            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                f.inverse();
                f.norm();
            }

            x = new ctx.BIG(0);
            x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);

            n = new ctx.BIG(x); //n.copy(x);
            K = new ctx.ECP2();

            if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BN) {
                n.pmul(6);
                if (ctx.ECP.SIGN_OF_X == ctx.ECP.POSITIVEX) {
                    n.inc(2)
                } else {
                    n.dec(2);
                }
            } else {
                n.copy(x);
            }
            n.norm();

            n3 = new ctx.BIG(n);
            n3.pmul(3);
            n3.norm();

            Qx = new ctx.FP(Q.getx()); //Qx.copy(Q.getx());
            Qy = new ctx.FP(Q.gety()); //Qy.copy(Q.gety());

            Sx = new ctx.FP(S.getx()); //Sx.copy(S.getx());
            Sy = new ctx.FP(S.gety()); //Sy.copy(S.gety());

            A = new ctx.ECP2();
            B = new ctx.ECP2();
            r = new ctx.FP12(1);

            A.copy(P);
            B.copy(R);
            nb = n3.nbits();

            for (var i = nb - 2; i >= 1; i--) {
                r.sqr();
                lv = PAIR.line(A, A, Qx, Qy);
                r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                lv = PAIR.line(B, B, Sx, Sy);
                r.smul(lv,ctx.ECP.SEXTIC_TWIST);

                bt=n3.bit(i)-n.bit(i);

                if (bt == 1) {
                    lv = PAIR.line(A, P, Qx, Qy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                    lv = PAIR.line(B, R, Sx, Sy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                }
                if (bt == -1) {
                    P.neg();
                    lv = PAIR.line(A, P, Qx, Qy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                    P.neg();
                    R.neg();
                    lv = PAIR.line(B, R, Sx, Sy);
                    r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                    R.neg();
                }
            }

            /* R-ate fixup required for BN curves */
            if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BN) {
                if (ctx.ECP.SIGN_OF_X == ctx.ECP.NEGATIVEX) {
                    r.conj();
                    A.neg();
                    B.neg();
                }
                K.copy(P);
                K.frob(f);

                lv = PAIR.line(A, K, Qx, Qy);
                r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                K.frob(f);
                K.neg();
                lv = PAIR.line(A, K, Qx, Qy);
                r.smul(lv,ctx.ECP.SEXTIC_TWIST);

                K.copy(R);
                K.frob(f);

                lv = PAIR.line(B, K, Sx, Sy);
                r.smul(lv,ctx.ECP.SEXTIC_TWIST);
                K.frob(f);
                K.neg();
                lv = PAIR.line(B, K, Sx, Sy);
                r.smul(lv,ctx.ECP.SEXTIC_TWIST);
            }

            return r;
        },

        /* final exponentiation - keep separate for multi-pairings and to avoid thrashing stack */
        fexp: function(m) {
            var fa, fb, f, x, r, lv,
                x0, x1, x2, x3, x4, x5,
                y0, y1, y2, y3;

            fa = new ctx.BIG(0);
            fa.rcopy(ctx.ROM_FIELD.Fra);
            fb = new ctx.BIG(0);
            fb.rcopy(ctx.ROM_FIELD.Frb);
            f = new ctx.FP2(fa, fb);
            x = new ctx.BIG(0);
            x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);

            r = new ctx.FP12(m); //r.copy(m);

            /* Easy part of final exp */
            lv = new ctx.FP12(r); //lv.copy(r);
            lv.inverse();
            r.conj();
            r.mul(lv);
            lv.copy(r);
            r.frob(f);
            r.frob(f);
            r.mul(lv);

            /* Hard part of final exp */
            if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BN) {
                lv.copy(r);
                lv.frob(f);
                x0 = new ctx.FP12(lv); //x0.copy(lv);
                x0.frob(f);
                lv.mul(r);
                x0.mul(lv);
                x0.frob(f);
                x1 = new ctx.FP12(r); //x1.copy(r);
                x1.conj();

                x4 = r.pow(x);
                if (ctx.ECP.SIGN_OF_X == ctx.ECP.POSITIVEX) {
                    x4.conj();
                }

                x3 = new ctx.FP12(x4); //x3.copy(x4);
                x3.frob(f);
                x2 = x4.pow(x);
                if (ctx.ECP.SIGN_OF_X == ctx.ECP.POSITIVEX) {
                    x2.conj();
                }
                x5 = new ctx.FP12(x2); /*x5.copy(x2);*/
                x5.conj();
                lv = x2.pow(x);
                if (ctx.ECP.SIGN_OF_X == ctx.ECP.POSITIVEX) {
                    lv.conj();
                }
                x2.frob(f);
                r.copy(x2);
                r.conj();

                x4.mul(r);
                x2.frob(f);

                r.copy(lv);
                r.frob(f);
                lv.mul(r);

                lv.usqr();
                lv.mul(x4);
                lv.mul(x5);
                r.copy(x3);
                r.mul(x5);
                r.mul(lv);
                lv.mul(x2);
                r.usqr();
                r.mul(lv);
                r.usqr();
                lv.copy(r);
                lv.mul(x1);
                r.mul(x0);
                lv.usqr();
                r.mul(lv);
                r.reduce();
            } else {
                // Ghamman & Fouotsa Method
                y0 = new ctx.FP12(r);
                y0.usqr();
                y1 = y0.pow(x);
                if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                    y1.conj();
                }
                x.fshr(1);
                y2 = y1.pow(x);
                if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                    y2.conj();
                }
                x.fshl(1);
                y3 = new ctx.FP12(r);
                y3.conj();
                y1.mul(y3);

                y1.conj();
                y1.mul(y2);

                y2 = y1.pow(x);
                if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                    y2.conj();
                }

                y3 = y2.pow(x);
                if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                    y3.conj();
                }
                y1.conj();
                y3.mul(y1);

                y1.conj();
                y1.frob(f);
                y1.frob(f);
                y1.frob(f);
                y2.frob(f);
                y2.frob(f);
                y1.mul(y2);

                y2 = y3.pow(x);
                if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                    y2.conj();
                }
                y2.mul(y0);
                y2.mul(r);

                y1.mul(y2);
                y2.copy(y3);
                y2.frob(f);
                y1.mul(y2);
                r.copy(y1);
                r.reduce();
            }

            return r;
        }
    };

    /* GLV method */
    PAIR.glv = function(e) {
        var u = [],
            t, q, v, d, x, x2, i, j;

        if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BN) {
            t = new ctx.BIG(0);
            q = new ctx.BIG(0);
            v = [];

            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            for (i = 0; i < 2; i++) {
                t.rcopy(ctx.ROM_CURVE.CURVE_W[i]);
                d = ctx.BIG.mul(t, e);
                v[i] = new ctx.BIG(d.div(q));
                u[i] = new ctx.BIG(0);
            }

            u[0].copy(e);

            for (i = 0; i < 2; i++) {
                for (j = 0; j < 2; j++) {
                    t.rcopy(ctx.ROM_CURVE.CURVE_SB[j][i]);
                    t.copy(ctx.BIG.modmul(v[j], t, q));
                    u[i].add(q);
                    u[i].sub(t);
                    u[i].mod(q);
                }
            }
        } else { // -(x^2).P = (Beta.x,y)
            q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);
            x = new ctx.BIG(0);
            x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);
            x2 = ctx.BIG.smul(x, x);
            u[0] = new ctx.BIG(e);
            u[0].mod(x2);
            u[1] = new ctx.BIG(e);
            u[1].div(x2);
            u[1].rsub(q);
        }

        return u;
    };

    /* Galbraith & Scott Method */
    PAIR.gs = function(e) {
        var u = [],
            i, j, t, q, v, d, x, w;

        if (ctx.ECP.CURVE_PAIRING_TYPE == ctx.ECP.BN) {
            t = new ctx.BIG(0);
            q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            v = [];

            for (i = 0; i < 4; i++) {
                t.rcopy(ctx.ROM_CURVE.CURVE_WB[i]);
                d = ctx.BIG.mul(t, e);
                v[i] = new ctx.BIG(d.div(q));
                u[i] = new ctx.BIG(0);
            }

            u[0].copy(e);

            for (i = 0; i < 4; i++) {
                for (j = 0; j < 4; j++) {
                    t.rcopy(ctx.ROM_CURVE.CURVE_BB[j][i]);
                    t.copy(ctx.BIG.modmul(v[j], t, q));
                    u[i].add(q);
                    u[i].sub(t);
                    u[i].mod(q);
                }
            }
        } else {
            x = new ctx.BIG(0);
            x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);
            q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);
            w = new ctx.BIG(e);

            for (i = 0; i < 3; i++) {
                u[i] = new ctx.BIG(w);
                u[i].mod(x);
                w.div(x);
            }

            u[3] = new ctx.BIG(w);
            if (ctx.ECP.SIGN_OF_X==ctx.ECP.NEGATIVEX) {
                u[1].copy(ctx.BIG.modneg(u[1], q));
                u[3].copy(ctx.BIG.modneg(u[3], q));
            }
        }

        return u;
    };

    /* Multiply P by e in group G1 */
    PAIR.G1mul = function(P, e) {
        var R, Q, q, bcru, cru, t, u, np, nn;

        if (ctx.ROM_CURVE.USE_GLV) {
            P.affine();
            R = new ctx.ECP();
            R.copy(P);
            Q = new ctx.ECP();
            Q.copy(P);
            q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);
            bcru = new ctx.BIG(0);
            bcru.rcopy(ctx.ROM_CURVE.CURVE_Cru);
            cru = new ctx.FP(bcru);
            t = new ctx.BIG(0);
            u = PAIR.glv(e);

            Q.getx().mul(cru);

            np = u[0].nbits();
            t.copy(ctx.BIG.modneg(u[0], q));
            nn = t.nbits();
            if (nn < np) {
                u[0].copy(t);
                R.neg();
            }

            np = u[1].nbits();
            t.copy(ctx.BIG.modneg(u[1], q));
            nn = t.nbits();
            if (nn < np) {
                u[1].copy(t);
                Q.neg();
            }

            R = R.mul2(u[0], Q, u[1]);
        } else {
            R = P.mul(e);
        }

        return R;
    };

    /* Multiply P by e in group G2 */
    PAIR.G2mul = function(P, e) {
        var R, Q, fa, fb, f, q, u, t, i, np, nn;

        if (ctx.ROM_CURVE.USE_GS_G2) {
            Q = [];
            fa = new ctx.BIG(0);
            fa.rcopy(ctx.ROM_FIELD.Fra);
            fb = new ctx.BIG(0);
            fb.rcopy(ctx.ROM_FIELD.Frb);
            f = new ctx.FP2(fa, fb); //f.bset(fa,fb);

            if (ctx.ECP.SEXTIC_TWIST == ctx.ECP.M_TYPE) {
                f.inverse();
                f.norm();
            }

            q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);

            u = PAIR.gs(e);
            t = new ctx.BIG(0);
            P.affine();
            Q[0] = new ctx.ECP2();
            Q[0].copy(P);

            for (i = 1; i < 4; i++) {
                Q[i] = new ctx.ECP2();
                Q[i].copy(Q[i - 1]);
                Q[i].frob(f);
            }

            for (i = 0; i < 4; i++) {
                np = u[i].nbits();
                t.copy(ctx.BIG.modneg(u[i], q));
                nn = t.nbits();

                if (nn < np) {
                    u[i].copy(t);
                    Q[i].neg();
                }
            }

            R = ctx.ECP2.mul4(Q, u);
        } else {
            R = P.mul(e);
        }
        return R;
    };

    /* Note that this method requires a lot of RAM! Better to use compressed XTR method, see ctx.FP4.js */
    PAIR.GTpow = function(d, e) {
        var r, g, fa, fb, f, q, t, u, i, np, nn;

        if (ctx.ROM_CURVE.USE_GS_GT) {
            g = [];
            fa = new ctx.BIG(0);
            fa.rcopy(ctx.ROM_FIELD.Fra);
            fb = new ctx.BIG(0);
            fb.rcopy(ctx.ROM_FIELD.Frb);
            f = new ctx.FP2(fa, fb);
            q = new ctx.BIG(0);
            q.rcopy(ctx.ROM_CURVE.CURVE_Order);
            t = new ctx.BIG(0);
            u = PAIR.gs(e);

            g[0] = new ctx.FP12(d);

            for (i = 1; i < 4; i++) {
                g[i] = new ctx.FP12(0);
                g[i].copy(g[i - 1]);
                g[i].frob(f);
            }

            for (i = 0; i < 4; i++) {
                np = u[i].nbits();
                t.copy(ctx.BIG.modneg(u[i], q));
                nn = t.nbits();

                if (nn < np) {
                    u[i].copy(t);
                    g[i].conj();
                }
            }

            r = ctx.FP12.pow4(g, u);
        } else {
            r = d.pow(e);
        }

        return r;
    };

    /* test group membership - no longer needed */
    /* with GT-Strong curve, now only check that m!=1, conj(m)*m==1, and m.m^{p^4}=m^{p^2} */
    /*
    PAIR.GTmember= function(m)
    {
        if (m.isunity()) return false;
        var r=new ctx.FP12(m);
        r.conj();
        r.mul(m);
        if (!r.isunity()) return false;

        var fa=new ctx.BIG(0); fa.rcopy(ctx.ROM_FIELD.Fra);
        var fb=new ctx.BIG(0); fb.rcopy(ctx.ROM_FIELD.Frb);
        var f=new ctx.FP2(fa,fb); //f.bset(fa,fb);

        r.copy(m); r.frob(f); r.frob(f);
        var w=new ctx.FP12(r); w.frob(f); w.frob(f);
        w.mul(m);
        if (!ctx.ROM_CURVE.GT_STRONG)
        {
            if (!w.equals(r)) return false;
            var x=new ctx.BIG(0); x.rcopy(ctx.ROM_CURVE.CURVE_Bnx);
            r.copy(m); w=r.pow(x); w=w.pow(x);
            r.copy(w); r.sqr(); r.mul(w); r.sqr();
            w.copy(m); w.frob(f);
        }
        return w.equals(r);
    };
    */

    return PAIR;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports.PAIR = PAIR;
}

},{}],"./rand":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/*
 *   Cryptographic strong random number generator
 *
 *   Unguessable seed -> SHA -> PRNG internal state -> SHA -> random numbers
 *   Slow - but secure
 *
 *   See ftp://ftp.rsasecurity.com/pub/pdfs/bull-1.pdf for a justification
 */

/* Marsaglia & Zaman Random number generator constants */

var RAND = function(ctx) {
    "use strict";

    var RAND = function() {
        /* Cryptographically strong pseudo-random number generator */
        this.ira = []; /* random number...   */
        this.rndptr = 0; /* ...array & pointer */
        this.borrow = 0;
        this.pool_ptr = 0;
        this.pool = []; /* random pool */
        this.clean();
    };

    RAND.prototype = {
        NK: 21,
        NJ: 6,
        NV: 8,

        /* Terminate and clean up */
        clean: function() {
            var i;

            for (i = 0; i < 32; i++) {
                this.pool[i] = 0;
            }

            for (i = 0; i < this.NK; i++) {
                this.ira[i] = 0;
            }

            this.rndptr = 0;
            this.borrow = 0;
            this.pool_ptr = 0;
        },

        sbrand: function() { /* Marsaglia & Zaman random number generator */
            var i, k, pdiff, t;

            this.rndptr++;
            if (this.rndptr < this.NK) {
                return this.ira[this.rndptr];
            }

            this.rndptr = 0;

            for (i = 0, k = this.NK - this.NJ; i < this.NK; i++, k++) { /* calculate next NK values */
                if (k == this.NK) {
                    k = 0;
                }

                t = this.ira[k] >>> 0;
                pdiff = (t - this.ira[i] - this.borrow) | 0;
                pdiff >>>= 0; /* This is seriously weird shit. I got to do this to get a proper unsigned comparison... */

                if (pdiff < t) {
                    this.borrow = 0;
                }

                if (pdiff > t) {
                    this.borrow = 1;
                }

                this.ira[i] = (pdiff | 0);
            }

            return this.ira[0];
        },

        sirand: function(seed) {
            var m = 1,
                i, inn, t;

            this.borrow = 0;
            this.rndptr = 0;
            seed >>>= 0;
            this.ira[0] ^= seed;

            for (i = 1; i < this.NK; i++) { /* fill initialisation vector */
                inn = (this.NV * i) % this.NK;
                this.ira[inn] ^= m; /* note XOR */
                t = m;
                m = (seed - m) | 0;
                seed = t;
            }

            /* "warm-up" & stir the generator */
            for (i = 0; i < 10000; i++) {
                this.sbrand();
            }
        },

        fill_pool: function() {
            var sh = new ctx.HASH256(),
                i;

            for (i = 0; i < 128; i++) {
                sh.process(this.sbrand());
            }

            this.pool = sh.hash();
            this.pool_ptr = 0;
        },

        /* Initialize RNG with some real entropy from some external source */
        seed: function(rawlen, raw) { /* initialise from at least 128 byte string of raw random entropy */
            var sh = new ctx.HASH256(),
                digest = [],
                b = [],
                i;

            this.pool_ptr = 0;

            for (i = 0; i < this.NK; i++) {
                this.ira[i] = 0;
            }

            if (rawlen > 0) {
                for (i = 0; i < rawlen; i++) {
                    sh.process(raw[i]);
                }

                digest = sh.hash();

                /* initialise PRNG from distilled randomness */
                for (i = 0; i < 8; i++) {
                    b[0] = digest[4 * i];
                    b[1] = digest[4 * i + 1];
                    b[2] = digest[4 * i + 2];
                    b[3] = digest[4 * i + 3];
                    this.sirand(RAND.pack(b));
                }
            }

            this.fill_pool();
        },

        /* get random byte */
        getByte: function() {
            var r = this.pool[this.pool_ptr++];

            if (this.pool_ptr >= 32) {
                this.fill_pool();
            }

            return (r & 0xff);
        }
    };

    RAND.pack = function(b) { /* pack 4 bytes into a 32-bit Word */
        return (((b[3]) & 0xff) << 24) | ((b[2] & 0xff) << 16) | ((b[1] & 0xff) << 8) | (b[0] & 0xff);
    };

    return RAND;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports.RAND = RAND;
}

},{}],"./rom_curve":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* Fixed Data in ROM - Field and Curve parameters */

var ROM_CURVE_ANSSI,
    ROM_CURVE_BLS383,
    ROM_CURVE_BLS461,
    ROM_CURVE_FP256BN,
    ROM_CURVE_FP512BN,
    ROM_CURVE_BN254,
    ROM_CURVE_BN254CX,
    ROM_CURVE_BRAINPOOL,
    ROM_CURVE_C25519,
    ROM_CURVE_C41417,
    ROM_CURVE_ED25519,
    ROM_CURVE_GOLDILOCKS,
    ROM_CURVE_HIFIVE,
    ROM_CURVE_NIST256,
    ROM_CURVE_NIST384,
    ROM_CURVE_NIST521,
    ROM_CURVE_NUMS256E,
    ROM_CURVE_NUMS256W,
    ROM_CURVE_NUMS384E,
    ROM_CURVE_NUMS384W,
    ROM_CURVE_NUMS512E,
    ROM_CURVE_NUMS512W;

ROM_CURVE_ANSSI = function() {

    var ROM_CURVE_ANSSI = {

        // ANSSI curve

        CURVE_A: -3,
        CURVE_B_I: 0,
        CURVE_B: [0x7BB73F, 0xED967B, 0x803075, 0xE4B1A1, 0xEC0C9A, 0xC00FDF, 0x754A44, 0xD4ABA, 0x28A930, 0x3FCA54, 0xEE35],
        CURVE_Order: [0xD655E1, 0xD459C6, 0x941FFD, 0x40D2BF, 0xDC67E1, 0x435B53, 0xE8CE42, 0x10126D, 0x3AD58F, 0x178C0B, 0xF1FD],
        CURVE_Gx: [0x8F5CFF, 0x7A2DD9, 0x164C9, 0xAF98B7, 0x27D2DC, 0x23958C, 0x4749D4, 0x31183D, 0xC139EB, 0xD4C356, 0xB6B3],
        CURVE_Gy: [0x62CFB, 0x5A1554, 0xE18311, 0xE8E4C9, 0x1C307, 0xEF8C27, 0xF0F3EC, 0x1F9271, 0xB20491, 0xE0F7C8, 0x6142],

    };
    return ROM_CURVE_ANSSI;
};

ROM_CURVE_BLS383 = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_BLS383 = {

        // BLS383 Curve
        // Base Bits= 23

        CURVE_A: 0,
        CURVE_B_I: 9,
        CURVE_B: [0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x7FF001, 0x700001, 0x6003FF, 0x387F3, 0x4BFDE0, 0xBDBE3, 0x127, 0x3D18, 0x7F910, 0x198800, 0x190401, 0xA, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gx: [0x10786B, 0x36691A, 0x2B4356, 0x71FAA, 0x33477C, 0xAF173, 0x496DCD, 0x37B2DF, 0x4007BB, 0x389ED5, 0x3FD5FA, 0x7EAC18, 0x6EC02E, 0x3F11F6, 0x262B6E, 0x67725E, 0xB08],
        CURVE_Gy: [0x145DDB, 0x34047A, 0x5F3017, 0x462FF7, 0x713F51, 0x5654CD, 0x3B0D18, 0x492FAB, 0x19C7A, 0x7D2DE6, 0x660488, 0x30823, 0x5BE599, 0x215B1E, 0x1C4120, 0x499BB, 0x1F39],

        CURVE_Bnx: [0x40, 0x2000, 0x44000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Cof: [0x52B, 0x54000, 0x328000, 0x555559, 0x55560A, 0xC0A, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Cru: [0x2155A9, 0x5589DB, 0x78F68E, 0x43B0F2, 0x5DF2FE, 0x4C64C4, 0x37EAB7, 0x1AD35E, 0x128D30, 0x6A246, 0x6FAB5A, 0x5F9D15, 0x24190D, 0x756408, 0x7DD717, 0x104054, 0x7AC5],
        CURVE_Pxa: [0x2C9472, 0x3310B7, 0xDB581, 0xEF16E, 0x77C4D3, 0x119114, 0x72430C, 0x447E5E, 0x1971C6, 0x4E53E0, 0x710FC5, 0x349A9C, 0x6B8BF3, 0x4B4AC3, 0x2FF607, 0x3915AB, 0x4D50],
        CURVE_Pxb: [0x72AB23, 0x17AF44, 0x73A26D, 0x6A7A26, 0x47AF19, 0x640D46, 0x5BDEE4, 0xCFD9F, 0x53E2A8, 0x5CAE3B, 0x58D75F, 0x515D1D, 0x1A1263, 0x18F018, 0x16EB0A, 0x30BE1F, 0xEE3],
        CURVE_Pya: [0x7BD4FD, 0x24612E, 0x7F1A07, 0x3906FE, 0x40B660, 0x191341, 0x7F2564, 0x143D20, 0x3CF878, 0x4A5C3F, 0x53BB9, 0x8E118, 0x3325E0, 0x7102D7, 0x170A21, 0x42CD0, 0x8F4],
        CURVE_Pyb: [0x2C4CE6, 0x44144A, 0x32297, 0x3A57FA, 0x35907A, 0x4891DE, 0x5D8290, 0x50CCA0, 0x2B0FD, 0x13FFDF, 0x6353A9, 0x794D0, 0x4997BA, 0x6F70DC, 0x4AB1F, 0x5DD446, 0x1DCA],
        CURVE_W: [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        CURVE_SB: [
            [
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ]
        ],
        CURVE_WB: [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        CURVE_BB: [
            [
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ]
        ],

        USE_GLV: true,
        USE_GS_G2: true,
        USE_GS_GT: true,
        GT_STRONG: false,

        //debug: false,

    };

    return ROM_CURVE_BLS383;
};

ROM_CURVE_BLS461 = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_BLS461 = {

        // BLS461 Curve
        // Base Bits= 23

        CURVE_A: 0,
        CURVE_B_I: 9,
        CURVE_B: [0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x1, 0x0, 0x700000, 0x7F7FFF, 0x7FEFF, 0x22000, 0x7F2000, 0x7E00BF, 0xE801, 0x40BFA0, 0x5FF, 0x7FE00C, 0x7FFF7F, 0x1FF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gx: [0x5EE93D, 0x4D515, 0x504534, 0x773A5B, 0x2D9C00, 0x6358FE, 0x6606D4, 0x4114E1, 0x4DC921, 0x21A6AC, 0x282599, 0x7BE149, 0x436166, 0x45632E, 0x1A2FA4, 0x38967B, 0xC8132, 0x476E74, 0x3A66D1, 0x56873A, 0x0],
        CURVE_Gy: [0x51D465, 0x462AF5, 0x51C3DD, 0x64627F, 0x517884, 0x71A42B, 0x6799A, 0x2CE854, 0x245F49, 0x15CB86, 0x2E1244, 0x45FD20, 0x16EECB, 0x3F197D, 0x3322FE, 0x1793BD, 0x5F1C3F, 0x3ED192, 0x452CC1, 0x3BDE6D, 0x0],

        CURVE_Bnx: [0x0, 0x7FFC00, 0x7FFFEF, 0xFF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Cof: [0x2AAAAB, 0x7FFD55, 0x5AAA9F, 0x5580AA, 0x7D55AA, 0x2A9FFF, 0x5555, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Cru: [0x7FFFFE, 0x3FF, 0x10, 0x7FFF00, 0x7FFE7F, 0x61FFED, 0x311F, 0x630239, 0x6DB7BC, 0x622AF2, 0x73D1DD, 0x43AA19, 0x3F0E89, 0xA04C2, 0x581400, 0x7F5FFF, 0x1FFFF, 0x0, 0x0, 0x0, 0x0],
        CURVE_Pxa: [0x50A37C, 0x20630D, 0x31196D, 0x173AEE, 0x1C2E49, 0x2D0F15, 0x7E467, 0x7AB270, 0x74FF92, 0x610DB6, 0x19A00F, 0x36AC0D, 0x6D78D4, 0x78520F, 0x224BE5, 0x1E1386, 0x767945, 0x4A1535, 0x4E281A, 0x662A0, 0x1],
        CURVE_Pxb: [0x41C0AD, 0x395185, 0x37A7E1, 0x6212E5, 0x16CD66, 0x4512C1, 0x4A546, 0x200D63, 0x3EBEE2, 0x7AA535, 0x7D96C5, 0x504E99, 0x45AF5B, 0x6E3DA9, 0x4B9350, 0x123533, 0x2279D2, 0x1D46F9, 0x53F96B, 0x4AE0FD, 0x0],
        CURVE_Pya: [0x2FB006, 0x218360, 0xCDF33, 0x525095, 0x53D194, 0x125912, 0x5833F3, 0x6345A4, 0xF39F, 0x1E7536, 0x7B46E8, 0x3EDDE2, 0x4DFD8A, 0x5EF53, 0x3489F3, 0x7A739F, 0x6070F4, 0x74FCCE, 0x1239FA, 0x113564, 0x0],
        CURVE_Pyb: [0x71457C, 0xD5BFB, 0x2A294, 0x6E0261, 0x4D6A31, 0x6DC7F6, 0x26A3C4, 0x2B3475, 0x64492F, 0x2E7877, 0x19E84A, 0x25F55D, 0x220BE7, 0x5C70AD, 0x7C1310, 0x228AB, 0x2AB1D0, 0x6805D4, 0x6D3EAE, 0x71C080, 0x0],
        CURVE_W: [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        CURVE_SB: [
            [
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ]
        ],
        CURVE_WB: [
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        CURVE_BB: [
            [
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ]
        ],

        USE_GLV: true,
        USE_GS_G2: true,
        USE_GS_GT: true,
        GT_STRONG: false,

        //debug: false,

    };

    return ROM_CURVE_BLS461;
};

ROM_CURVE_FP256BN = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_FP256BN = {

        // FP256BN Curve
        // Base Bits= 24

        CURVE_A: 0,
        CURVE_B_I: 3,
        CURVE_B: [0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0xB500D, 0x536CD1, 0x1AF62D, 0x129992, 0xDC65FB, 0xA49E0C, 0x5EEE71, 0x46E5F2, 0xFCF0CD, 0xFFFFFF, 0xFFFF],
        CURVE_Gx: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],

        CURVE_Bnx: [0xB0A801, 0xF5C030, 0x6882, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Cof: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Cru: [0xA1B807, 0xA24A3, 0x1EDB1C, 0xF1932D, 0xCDD79D, 0x18659B, 0x409210, 0x3988E1, 0x1, 0x0, 0x0],
        CURVE_Pxa: [0xC09EFB, 0x16B689, 0x3CD226, 0x12BF84, 0x1C539A, 0x913ACE, 0x577C28, 0x28560F, 0xC96C20, 0x3350B4, 0xFE0C],
        CURVE_Pxb: [0x7E6A2B, 0xED34A3, 0x89D269, 0x87D035, 0xDD78E2, 0x13B924, 0xC637D8, 0xDB5AE1, 0x8AC054, 0x605773, 0x4EA6],
        CURVE_Pya: [0xDC27FF, 0xB481BE, 0x48E909, 0x8D6158, 0xCB2475, 0x3E51EF, 0x75124E, 0x76770D, 0x42A3B3, 0x46E7C5, 0x7020],
        CURVE_Pyb: [0xAD049B, 0x81114A, 0xB3E012, 0x821A98, 0x4CBE80, 0xB29F8B, 0x49297E, 0x42EEA6, 0x88C290, 0xE3BCD3, 0x554],

        CURVE_W: [
            [0x54003, 0x36E1B, 0x663AF0, 0xFFFE78, 0xFFFFFF, 0xFF, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x615001, 0xEB8061, 0xD105, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        CURVE_SB: [
            [
                [0x669004, 0xEEEE7C, 0x670BF5, 0xFFFE78, 0xFFFFFF, 0xFF, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x615001, 0xEB8061, 0xD105, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0x615001, 0xEB8061, 0xD105, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x6100A, 0x4FFEB6, 0xB4BB3D, 0x129B19, 0xDC65FB, 0xA49D0C, 0x5EEE71, 0x46E5F2, 0xFCF0CD, 0xFFFFFF, 0xFFFF]
            ]
        ],
        CURVE_WB: [
            [0x30A800, 0x678F0D, 0xCC1020, 0x5554D2, 0x555555, 0x55, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x7DC805, 0x764C0D, 0xAD1AD6, 0xA10BC3, 0xDE8FBE, 0x104467, 0x806160, 0xD105EB, 0x0, 0x0, 0x0],
            [0x173803, 0xB6061F, 0xD6C1AC, 0x5085E1, 0xEF47DF, 0x82233, 0xC030B0, 0x6882F5, 0x0, 0x0, 0x0],
            [0x91F801, 0x530F6E, 0xCCE126, 0x5554D2, 0x555555, 0x55, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        CURVE_BB: [
            [
                [0x5AA80D, 0x5DACA0, 0x1A8DAA, 0x129992, 0xDC65FB, 0xA49E0C, 0x5EEE71, 0x46E5F2, 0xFCF0CD, 0xFFFFFF, 0xFFFF],
                [0x5AA80C, 0x5DACA0, 0x1A8DAA, 0x129992, 0xDC65FB, 0xA49E0C, 0x5EEE71, 0x46E5F2, 0xFCF0CD, 0xFFFFFF, 0xFFFF],
                [0x5AA80C, 0x5DACA0, 0x1A8DAA, 0x129992, 0xDC65FB, 0xA49E0C, 0x5EEE71, 0x46E5F2, 0xFCF0CD, 0xFFFFFF, 0xFFFF],
                [0x615002, 0xEB8061, 0xD105, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0x615001, 0xEB8061, 0xD105, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x5AA80C, 0x5DACA0, 0x1A8DAA, 0x129992, 0xDC65FB, 0xA49E0C, 0x5EEE71, 0x46E5F2, 0xFCF0CD, 0xFFFFFF, 0xFFFF],
                [0x5AA80D, 0x5DACA0, 0x1A8DAA, 0x129992, 0xDC65FB, 0xA49E0C, 0x5EEE71, 0x46E5F2, 0xFCF0CD, 0xFFFFFF, 0xFFFF],
                [0x5AA80C, 0x5DACA0, 0x1A8DAA, 0x129992, 0xDC65FB, 0xA49E0C, 0x5EEE71, 0x46E5F2, 0xFCF0CD, 0xFFFFFF, 0xFFFF]
            ],
            [
                [0x615002, 0xEB8061, 0xD105, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x615001, 0xEB8061, 0xD105, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x615001, 0xEB8061, 0xD105, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x615001, 0xEB8061, 0xD105, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0xB0A802, 0xF5C030, 0x6882, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0xC2A002, 0xD700C2, 0x1A20B, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0xAA000A, 0x67EC6F, 0x1A2527, 0x129992, 0xDC65FB, 0xA49E0C, 0x5EEE71, 0x46E5F2, 0xFCF0CD, 0xFFFFFF, 0xFFFF],
                [0xB0A802, 0xF5C030, 0x6882, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ]
        ],

        USE_GLV: true,
        USE_GS_G2: true,
        USE_GS_GT: true,
        GT_STRONG: false,

        //debug: false,

    };

    return ROM_CURVE_FP256BN;
};

ROM_CURVE_FP512BN = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_FP512BN = {

        // FP512BN Curve

        // Base Bits= 23


        CURVE_A: 0,
        CURVE_B_I: 3,
        CURVE_B: [0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x1A09ED, 0x14BEA3, 0x501A99, 0x27CD15, 0x313E0, 0x346942, 0x2AC99E, 0x4632EF, 0x18B8E4, 0x3D597D, 0x451B3C, 0x77A22, 0x3C111B, 0x78177C, 0x32D4C1, 0x5D0EC, 0x7F01C6, 0x7FF3D8, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F],
        CURVE_Gx: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],

        CURVE_Bnx: [0x1BD80F, 0xD76BC, 0x4042CC, 0x587BF, 0x2F5C03, 0xD10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Cof: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Cru: [0x79298A, 0x2C4138, 0x52C1C, 0x5C58BE, 0x6E6799, 0x1255D9, 0x2F9498, 0x43C4B3, 0x507ACD, 0x11384E, 0x1D2C80, 0x8FD18, 0x78EF76, 0x71D459, 0x2E1ACD, 0x1530A3, 0x7DC83D, 0x7FF3D8, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F],
        CURVE_Pxa: [0x3646B5, 0x52DC1B, 0x7A3C1E, 0x48397F, 0xF8731, 0x71E443, 0x6F2EF1, 0x2BDF10, 0x4DC6DC, 0x70C6A2, 0x40914D, 0x3C6685, 0x5A57CC, 0x3736AF, 0x4D63C3, 0x5DE94D, 0x6A1E4B, 0x25E79, 0x6E9D, 0x244AC4, 0x1E1386, 0x62CA67, 0xE],
        CURVE_Pxb: [0xAE0E9, 0x17DFB5, 0x6CF6D7, 0x6C4488, 0x4A411C, 0x5B9C81, 0x4E0F56, 0x286B70, 0x6E0D5E, 0x650AA4, 0x607889, 0x5CA6CB, 0x302566, 0x48ED51, 0x1B1BBC, 0x532B6E, 0x34825E, 0x157D1, 0x6D311A, 0x3F3644, 0x3F8506, 0x38279, 0x12],
        CURVE_Pya: [0x5E67A1, 0x6255B, 0x178920, 0xAF7DC, 0x217AD6, 0x778B9B, 0xA022D, 0x11892A, 0x3E8EDD, 0x7BD82A, 0x5B3462, 0x34CEA5, 0x65C158, 0x1BA07D, 0x5982BF, 0x42D8EF, 0x4F2770, 0x19746E, 0x3BD6AC, 0x3DC149, 0x4C827C, 0x603D90, 0x1B],
        CURVE_Pyb: [0x4F8E8B, 0x630D90, 0x5A162D, 0x25FBB0, 0x5C222, 0x11BFE, 0x7B89E7, 0x18856B, 0x714A4, 0x7C5CA, 0xA25FF, 0xCA0ED, 0x3D0496, 0x61936C, 0x46219E, 0xA1C60, 0x591F02, 0x62BEEB, 0xD9030, 0x3C18D6, 0x48B04E, 0x34779D, 0x14],
        CURVE_W: [
            [0x34583, 0x712E93, 0x4FC443, 0x68B50B, 0x5FB911, 0x47FD2C, 0x7FFF3D, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x37B01F, 0x1AED78, 0x8598, 0xB0F7F, 0x5EB806, 0x1A20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        CURVE_SB: [
            [
                [0x4B9564, 0x56411A, 0x4F3EAB, 0x5DA58C, 0x1010B, 0x47E30C, 0x7FFF3D, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x6259CE, 0x79D12A, 0x4F9500, 0x1CBD96, 0x245BDA, 0x344F21, 0x2AC99E, 0x4632EF, 0x18B8E4, 0x3D597D, 0x451B3C, 0x77A22, 0x3C111B, 0x78177C, 0x32D4C1, 0x5D0EC, 0x7F01C6, 0x7FF3D8, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F]
            ],
            [
                [0x37B01F, 0x1AED78, 0x8598, 0xB0F7F, 0x5EB806, 0x1A20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x34583, 0x712E93, 0x4FC443, 0x68B50B, 0x5FB911, 0x47FD2C, 0x7FFF3D, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ]
        ],
        CURVE_WB: [
            [0x5A29F0, 0x66D56A, 0x305B6A, 0x2C1E98, 0x442C60, 0x42BF7F, 0x555514, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x355D4B, 0x25744, 0x45FBAC, 0x6BFC27, 0x20FC1F, 0x6BCB9E, 0x2778AE, 0x2C497D, 0x5AD40F, 0x72C0C9, 0x4549D2, 0x29A8B1, 0x576BC3, 0x42CC1, 0x587BF8, 0x75C030, 0xD105, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x289AAD, 0x7E700, 0x431F3C, 0x38C1F3, 0x282C11, 0x35EC57, 0x53BC57, 0x5624BE, 0x6D6A07, 0x396064, 0x62A4E9, 0x54D458, 0x6BB5E1, 0x21660, 0x2C3DFC, 0x7AE018, 0x6882, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x2279D1, 0x4BE7F2, 0x2FD5D2, 0x210F19, 0x65745A, 0x42A55E, 0x555514, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        CURVE_BB: [
            [
                [0x1BD810, 0xD76BC, 0x4042CC, 0x587BF, 0x2F5C03, 0xD10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x1BD80F, 0xD76BC, 0x4042CC, 0x587BF, 0x2F5C03, 0xD10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x1BD80F, 0xD76BC, 0x4042CC, 0x587BF, 0x2F5C03, 0xD10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x6259CF, 0x79D12A, 0x4F9500, 0x1CBD96, 0x245BDA, 0x344F21, 0x2AC99E, 0x4632EF, 0x18B8E4, 0x3D597D, 0x451B3C, 0x77A22, 0x3C111B, 0x78177C, 0x32D4C1, 0x5D0EC, 0x7F01C6, 0x7FF3D8, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F]
            ],
            [
                [0x37B01F, 0x1AED78, 0x8598, 0xB0F7F, 0x5EB806, 0x1A20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x7E31DE, 0x747E6, 0xFD7CD, 0x224556, 0x53B7DD, 0x345C31, 0x2AC99E, 0x4632EF, 0x18B8E4, 0x3D597D, 0x451B3C, 0x77A22, 0x3C111B, 0x78177C, 0x32D4C1, 0x5D0EC, 0x7F01C6, 0x7FF3D8, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F],
                [0x7E31DD, 0x747E6, 0xFD7CD, 0x224556, 0x53B7DD, 0x345C31, 0x2AC99E, 0x4632EF, 0x18B8E4, 0x3D597D, 0x451B3C, 0x77A22, 0x3C111B, 0x78177C, 0x32D4C1, 0x5D0EC, 0x7F01C6, 0x7FF3D8, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F],
                [0x7E31DE, 0x747E6, 0xFD7CD, 0x224556, 0x53B7DD, 0x345C31, 0x2AC99E, 0x4632EF, 0x18B8E4, 0x3D597D, 0x451B3C, 0x77A22, 0x3C111B, 0x78177C, 0x32D4C1, 0x5D0EC, 0x7F01C6, 0x7FF3D8, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F]
            ],
            [
                [0x37B01E, 0x1AED78, 0x8598, 0xB0F7F, 0x5EB806, 0x1A20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x37B01F, 0x1AED78, 0x8598, 0xB0F7F, 0x5EB806, 0x1A20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x37B01F, 0x1AED78, 0x8598, 0xB0F7F, 0x5EB806, 0x1A20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x37B01F, 0x1AED78, 0x8598, 0xB0F7F, 0x5EB806, 0x1A20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0x7E31DF, 0x0747E6, 0x0FD7CD, 0x224556, 0x53B7DD, 0x345C31, 0x2AC99E, 0x4632EF, 0x18B8E4, 0x3D597D, 0x451B3C, 0x77A22, 0x3C111B, 0x78177C, 0x32D4C1, 0x5D0EC, 0x7F01C6, 0x7FF3D8, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F],
                [0x2AA9AF, 0x5EE3B2, 0x4F0F68, 0x11AE17, 0x45A3D4, 0x343500, 0x2AC99E, 0x4632EF, 0x18B8E4, 0x3D597D, 0x451B3C, 0x77A22, 0x3C111B, 0x78177C, 0x32D4C1, 0x5D0EC, 0x7F01C6, 0x7FF3D8, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F],
                [0x37B01D, 0x1AED78, 0x008598, 0x0B0F7F, 0x5EB806, 0x001A20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x7E31DF, 0x0747E6, 0x0FD7CD, 0x224556, 0x53B7DD, 0x345C31, 0x2AC99E, 0x4632EF, 0x18B8E4, 0x3D597D, 0x451B3C, 0x77A22, 0x3C111B, 0x78177C, 0x32D4C1, 0x5D0EC, 0x7F01C6, 0x7FF3D8, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F]
            ]
        ],

        USE_GLV: true,
        USE_GS_G2: true,
        USE_GS_GT: true,
        GT_STRONG: false,

        //debug: false,

    };

    return ROM_CURVE_FP512BN;
};

ROM_CURVE_BN254 = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_BN254 = {

        // BN254 Curve

        // Base Bits= 24

        CURVE_A: 0,
        CURVE_B_I: 2,
        CURVE_B: [0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0xD, 0x0, 0x10A100, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
        CURVE_Gx: [0x12, 0x0, 0x13A700, 0x0, 0x210000, 0x861, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
        CURVE_Gy: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],

        CURVE_Bnx: [0x1, 0x0, 0x4080, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Cof: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Cru: [0x7, 0x0, 0x6CD80, 0x0, 0x90000, 0x249, 0x400000, 0x49B362, 0x0, 0x0, 0x0],
        CURVE_Pxa: [0x3FB2B, 0x4224C8, 0xD91EE, 0x4898BF, 0x648BBB, 0xEDB6A4, 0x7E8C61, 0xEB8D8C, 0x9EB62F, 0x10BB51, 0x61A],
        CURVE_Pxb: [0xD54CF3, 0x34C1E7, 0xB70D8C, 0xAE3784, 0x4D746B, 0xAA5B1F, 0x8C5982, 0x310AA7, 0x737833, 0xAAF9BA, 0x516],
        CURVE_Pya: [0xCD2B9A, 0xE07891, 0xBD19F0, 0xBDBE09, 0xBD0AE6, 0x822329, 0x96698C, 0x9A90E0, 0xAF9343, 0x97A06B, 0x218],
        CURVE_Pyb: [0x3ACE9B, 0x1AEC6B, 0x578A2D, 0xD739C9, 0x9006FF, 0x8D37B0, 0x56F5F3, 0x8F6D44, 0x8B1526, 0x2B0E7C, 0xEBB],
        CURVE_W: [
            [0x3, 0x0, 0x20400, 0x0, 0x818000, 0x61, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x1, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        CURVE_SB: [
            [
                [0x4, 0x0, 0x28500, 0x0, 0x818000, 0x61, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x1, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0x1, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0xA, 0x0, 0xE9D00, 0x0, 0x1E0000, 0x79E, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523]
            ]
        ],
        CURVE_WB: [
            [0x0, 0x0, 0x4080, 0x0, 0x808000, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x5, 0x0, 0x54A80, 0x0, 0x70000, 0x1C7, 0x800000, 0x312241, 0x0, 0x0, 0x0],
            [0x3, 0x0, 0x2C580, 0x0, 0x838000, 0xE3, 0xC00000, 0x189120, 0x0, 0x0, 0x0],
            [0x1, 0x0, 0xC180, 0x0, 0x808000, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        CURVE_BB: [
            [
                [0xD, 0x0, 0x106080, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
                [0xC, 0x0, 0x106080, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
                [0xC, 0x0, 0x106080, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
                [0x2, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0x1, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0xC, 0x0, 0x106080, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
                [0xD, 0x0, 0x106080, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
                [0xC, 0x0, 0x106080, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523]
            ],
            [
                [0x2, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x1, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x1, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x1, 0x0, 0x8100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0x2, 0x0, 0x4080, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x2, 0x0, 0x10200, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0xA, 0x0, 0x102000, 0x0, 0x9F8000, 0x7FF, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
                [0x2, 0x0, 0x4080, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ]
        ],

        USE_GLV: true,
        USE_GS_G2: true,
        USE_GS_GT: true,
        GT_STRONG: false,

        //debug: false,
    };

    return ROM_CURVE_BN254;
};

ROM_CURVE_BN254CX = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_BN254CX = {

        // BN254CX Curve
        // Base Bits= 24

        CURVE_A: 0,
        CURVE_B_I: 2,
        CURVE_B: [0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0xEB1F6D, 0xC0A636, 0xCEBE11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
        CURVE_Gx: [0x1B55B2, 0x23EF5C, 0xE1BE66, 0x18093E, 0x3FD6EE, 0x66D324, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
        CURVE_Gy: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],

        CURVE_Bnx: [0xC012B1, 0x3, 0x4000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Cof: [0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Cru: [0x235C97, 0x931794, 0x5631E0, 0x71EF87, 0xBDDF64, 0x3F1440, 0xCA8, 0x480000, 0x0, 0x0, 0x0],

        CURVE_Pxa: [0xD2EC74,0x1CEEE4,0x26C085,0xA03E27,0x7C85BF,0x4BBB90,0xF5C3,0x358B25,0x53B256,0x2D2C70,0x1968],
        CURVE_Pxb: [0x29CFE1,0x8E8B2E,0xF47A5,0xC209C3,0x1B97B0,0x9743F8,0x37A8E9,0xA011C9,0x19F64A,0xB9EC3E,0x1466],
        CURVE_Pya: [0xBE09F,0xFCEBCF,0xB30CFB,0x847EC1,0x61B33D,0xE20963,0x157DAE,0xD81E22,0x332B8D,0xEDD972,0xA79],
        CURVE_Pyb: [0x98EE9D,0x4B2288,0xEBED90,0x69D2ED,0x864EA5,0x3461C2,0x512D8D,0x35C6E4,0xC4C090,0xC39EC,0x616],


        CURVE_W: [
            [0x2FEB83, 0x634916, 0x120054, 0xB4038, 0x0, 0x60, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x802561, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        CURVE_SB: [
            [
                [0xB010E4, 0x63491D, 0x128054, 0xB4038, 0x0, 0x60, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x802561, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0x802561, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0xBB33EA, 0x5D5D20, 0xBCBDBD, 0x188CE, 0x3FD6EE, 0x66D264, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400]
            ]
        ],
        CURVE_WB: [
            [0x7A84B0, 0x211856, 0xB0401C, 0x3C012, 0x0, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0],
            [0x220475, 0xF995BE, 0x9A36CD, 0xA8CA7F, 0x7E94ED, 0x2A0DC0, 0x870, 0x300000, 0x0, 0x0, 0x0],
            [0xF10B93, 0xFCCAE0, 0xCD3B66, 0xD4653F, 0x3F4A76, 0x1506E0, 0x438, 0x180000, 0x0, 0x0, 0x0],
            [0xFAAA11, 0x21185D, 0xB0C01C, 0x3C012, 0x0, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0]
        ],
        CURVE_BB: [
            [
                [0x2B0CBD, 0xC0A633, 0xCE7E11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
                [0x2B0CBC, 0xC0A633, 0xCE7E11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
                [0x2B0CBC, 0xC0A633, 0xCE7E11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
                [0x802562, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0x802561, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x2B0CBC, 0xC0A633, 0xCE7E11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
                [0x2B0CBD, 0xC0A633, 0xCE7E11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
                [0x2B0CBC, 0xC0A633, 0xCE7E11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400]
            ],
            [
                [0x802562, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x802561, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x802561, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x802561, 0x7, 0x8000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ],
            [
                [0xC012B2, 0x3, 0x4000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x4AC2, 0xF, 0x10000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
                [0x6AFA0A, 0xC0A62F, 0xCE3E11, 0xCC906, 0x3FD6EE, 0x66D2C4, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
                [0xC012B2, 0x3, 0x4000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            ]
        ],

        USE_GLV: true,
        USE_GS_G2: true,
        USE_GS_GT: true,
        GT_STRONG: false,

        //debug: false,

    };

    return ROM_CURVE_BN254CX;
};

ROM_CURVE_BRAINPOOL = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    /* Note that the original curve has been transformed to an isomorphic curve with A=-3 */


    var ROM_CURVE_BRAINPOOL = {

        // Brainpool curve
        // Base Bits= 24

        CURVE_A: -3,
        CURVE_B_I: 0,
        CURVE_B: [0xE92B04, 0x8101FE, 0x256AE5, 0xAF2F49, 0x93EBC4, 0x76B7BF, 0x733D0B, 0xFE66A7, 0xD84EA4, 0x61C430, 0x662C],
        CURVE_Order: [0x4856A7, 0xE8297, 0xF7901E, 0xB561A6, 0x397AA3, 0x8D718C, 0x909D83, 0x3E660A, 0xEEA9BC, 0x57DBA1, 0xA9FB],
        CURVE_Gx: [0x1305F4, 0x91562E, 0x2B79A1, 0x7AAFBC, 0xA142C4, 0x6149AF, 0xB23A65, 0x732213, 0xCFE7B7, 0xEB3CC1, 0xA3E8],
        CURVE_Gy: [0x25C9BE, 0xE8F35B, 0x1DAB, 0x39D027, 0xBCB6DE, 0x417E69, 0xE14644, 0x7F7B22, 0x39C56D, 0x6C8234, 0x2D99],
    };
    return ROM_CURVE_BRAINPOOL;
};

ROM_CURVE_C25519 = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_C25519 = {

        // C25519 Curve

        CURVE_A: 486662,
        CURVE_B_I: 0,
        CURVE_B: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0xF5D3ED, 0x631A5C, 0xD65812, 0xA2F79C, 0xDEF9DE, 0x14, 0x0, 0x0, 0x0, 0x0, 0x1000],
        CURVE_Gx: [0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    };
    return ROM_CURVE_C25519;
};

ROM_CURVE_C41417 = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_C41417 = {

        // C41417 curve
        CURVE_A: 1,
        CURVE_B_I: 3617,
        CURVE_B: [0xE21, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x6AF79, 0x69784, 0x1B0E7, 0x18F3C6, 0x338AD, 0xDBC70, 0x6022B, 0x533DC, 0x3CC924, 0x3FFFAC, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x7FFF],
        CURVE_Gx: [0xBC595, 0x204BCF, 0xC4FD3, 0x14DF19, 0x33FAA8, 0x4C069, 0x16BA11, 0x2AD35B, 0x1498A4, 0x15FFCD, 0x3EC7F, 0x27D130, 0xD4636, 0x9B97F, 0x631C3, 0x8630, 0x144330, 0x241450, 0x1A334],
        CURVE_Gy: [0x22, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],

    };

    return ROM_CURVE_C41417;
};

ROM_CURVE_ED25519 = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_ED25519 = {

        // ED25519 Curve

        CURVE_A: -1,
        CURVE_B_I: 0,
        CURVE_B: [0x5978A3, 0x4DCA13, 0xAB75EB, 0x4141D8, 0x700A4D, 0xE89800, 0x797779, 0x8CC740, 0x6FFE73, 0x6CEE2B, 0x5203],
        CURVE_Order: [0xF5D3ED, 0x631A5C, 0xD65812, 0xA2F79C, 0xDEF9DE, 0x14, 0x0, 0x0, 0x0, 0x0, 0x1000],
        CURVE_Gx: [0x25D51A, 0x2D608F, 0xB2C956, 0x9525A7, 0x2CC760, 0xDC5C69, 0x31FDD6, 0xC0A4E2, 0x6E53FE, 0x36D3CD, 0x2169],
        CURVE_Gy: [0x666658, 0x666666, 0x666666, 0x666666, 0x666666, 0x666666, 0x666666, 0x666666, 0x666666, 0x666666, 0x6666],


    };
    return ROM_CURVE_ED25519;
};

ROM_CURVE_GOLDILOCKS = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_GOLDILOCKS = {

        // GOLDILOCKS curve
        CURVE_A: 1,
        CURVE_B_I: -39081,
        CURVE_B: [0x7F6756, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7DFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FF],
        CURVE_Order: [0x5844F3, 0x52556, 0x548DE3, 0x6E2C7A, 0x4C2728, 0x52042D, 0x6BB58D, 0x276DA4, 0x23E9C4, 0x7EF994, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x1FF],
        CURVE_Gx: [0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x52AAAA, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555555, 0x2AAAAA, 0x555],
        CURVE_Gy: [0x1386ED, 0x779BD5, 0x2F6BAB, 0xE6D03, 0x4B2BED, 0x131777, 0x4E8A8C, 0x32B2C1, 0x44B80D, 0x6515B1, 0x5F8DB5, 0x426EBD, 0x7A0358, 0x6DDA, 0x21B0AC, 0x6B1028, 0xDB359, 0x15AE09, 0x17A58D, 0x570],
    };
    return ROM_CURVE_GOLDILOCKS;
};

ROM_CURVE_HIFIVE = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_HIFIVE = {

        // HIFIVE curve

        CURVE_A: 1,
        CURVE_B_I: 11111,
        CURVE_B: [0x2B67, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x1FA805, 0x2B2E7D, 0x29ECBE, 0x3FC9DD, 0xBD6B8, 0x530A18, 0x45057E, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x800],
        CURVE_Gx: [0xC, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Gy: [0x7E8632, 0xD0A0B, 0x6C4AFB, 0x501B2E, 0x55650C, 0x36DB6B, 0x1FBD0D, 0x61C08E, 0x314B46, 0x70A7A3, 0x587401, 0xC70E0, 0x56502E, 0x38C2D6, 0x303],

    };
    return ROM_CURVE_HIFIVE;
};

ROM_CURVE_NIST256 = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_NIST256 = {

        // NIST256 Curve
        CURVE_A: -3,
        CURVE_B_I: 0,
        CURVE_B: [0xD2604B, 0x3C3E27, 0xF63BCE, 0xCC53B0, 0x1D06B0, 0x86BC65, 0x557698, 0xB3EBBD, 0x3A93E7, 0x35D8AA, 0x5AC6],
        CURVE_Order: [0x632551, 0xCAC2FC, 0x84F3B9, 0xA7179E, 0xE6FAAD, 0xFFFFBC, 0xFFFFFF, 0xFFFFFF, 0x0, 0xFFFF00, 0xFFFF],
        CURVE_Gx: [0x98C296, 0x3945D8, 0xA0F4A1, 0x2DEB33, 0x37D81, 0x40F277, 0xE563A4, 0xF8BCE6, 0x2C4247, 0xD1F2E1, 0x6B17],
        CURVE_Gy: [0xBF51F5, 0x406837, 0xCECBB6, 0x6B315E, 0xCE3357, 0x9E162B, 0x4A7C0F, 0x8EE7EB, 0x1A7F9B, 0x42E2FE, 0x4FE3],

    };
    return ROM_CURVE_NIST256;
};

ROM_CURVE_NIST384 = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_NIST384 = {

        // NIST384 curve
        CURVE_A: -3,
        CURVE_B_I: 0,
        CURVE_B: [0x6C2AEF, 0x11DBA7, 0x74AA17, 0x51768C, 0x6398D8, 0x6B58CA, 0x5404E1, 0xA0447, 0x411203, 0x5DFD02, 0x607671, 0x4168C8, 0x56BE3F, 0x1311C0, 0xFB9F9, 0x17D3F1, 0xB331],
        CURVE_Order: [0x452973, 0x32D599, 0x6BB3B0, 0x45853B, 0x20DB24, 0x3BEB03, 0x7D0DCB, 0x31A6C0, 0x7FFFC7, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0xFFFF],
        CURVE_Gx: [0x760AB7, 0x3C70E4, 0x30E951, 0x7AA94B, 0x2F25DB, 0x470AA0, 0x20950A, 0x7BA0F0, 0x1B9859, 0x45174F, 0x3874ED, 0x56BA3, 0x71EF32, 0x71D638, 0x22C14D, 0x65115F, 0xAA87],
        CURVE_Gy: [0x6A0E5F, 0x3AF921, 0x75E90C, 0x6BF40C, 0xB1CE1, 0x18014C, 0x6D7C2E, 0x6D1889, 0x147CE9, 0x7A5134, 0x63D076, 0x16E14F, 0xBF929, 0x6BB3D3, 0x98B1B, 0x6F254B, 0x3617],
    };
    return ROM_CURVE_NIST384;
};

ROM_CURVE_NIST521 = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_NIST521 = {

        // NIST521 curve

        CURVE_A: -3,
        CURVE_B_I: 0,
        CURVE_B: [0x503F00, 0x3FA8D6, 0x47BD14, 0x6961A7, 0x3DF883, 0x60E6AE, 0x4EEC6F, 0x29605E, 0x137B16, 0x23D8FD, 0x5864E5, 0x84F0A, 0x1918EF, 0x771691, 0x6CC57C, 0x392DCC, 0x6EA2DA, 0x6D0A81, 0x688682, 0x50FC94, 0x18E1C9, 0x27D72C, 0x1465],
        CURVE_Order: [0x386409, 0x6E3D22, 0x3AEDBE, 0x4CE23D, 0x5C9B88, 0x3A0776, 0x3DC269, 0x6600A4, 0x166B7F, 0x77E5F, 0x461A1E, 0x7FFFD2, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFF],
        CURVE_Gx: [0x65BD66, 0x7C6385, 0x6FE5F9, 0x2B5214, 0xB3C18, 0x1BC669, 0x68BFEA, 0xEE093, 0x5928FE, 0x6FDFCE, 0x52D79, 0x69EDD5, 0x7606B4, 0x3F0515, 0x4FED48, 0x409C82, 0x429C64, 0x472B68, 0x7B2D98, 0x4E6CF1, 0x70404E, 0x31C0D6, 0x31A1],
        CURVE_Gy: [0x516650, 0x28ED3F, 0x222FA, 0x139612, 0x47086A, 0x6C26A7, 0x4FEB41, 0x285C80, 0x2640C5, 0x32BDE8, 0x5FB9CA, 0x733164, 0x517273, 0x2F5F7, 0x66D11A, 0x2224AB, 0x5998F5, 0x58FA37, 0x297ED0, 0x22E4, 0x9A3BC, 0x252D4F, 0x460E],
    };
    return ROM_CURVE_NIST521;
};

ROM_CURVE_NUMS256E = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_NUMS256E = {

        // NUMS256E Curve
        CURVE_A: 1,
        CURVE_B_I: -15342,
        CURVE_B: [0xFFC355, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFF],
        CURVE_Order: [0xDD4AF5, 0xB190EE, 0x9B1A47, 0x2F5943, 0x955AA5, 0x41, 0x0, 0x0, 0x0, 0x0, 0x4000],
        CURVE_Gx: [0xED13DA, 0xC0902E, 0x86A0DE, 0xE30835, 0x398A0E, 0x9BD60C, 0x5F6920, 0xCD1E3D, 0xEA237D, 0x14FB6A, 0x8A75],
        CURVE_Gy: [0x8A89E6, 0x16E779, 0xD32FA6, 0x10856E, 0x5F61D8, 0x801071, 0xD9A64B, 0xCE9665, 0xD925C7, 0x3E9FD9, 0x44D5],


    };
    return ROM_CURVE_NUMS256E;
};

ROM_CURVE_NUMS256W = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_NUMS256W = {

        // NUMS256W Curve
        CURVE_A: -3,
        CURVE_B_I: 152961,
        CURVE_B: [0x25581, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x51A825, 0x202947, 0x6020AB, 0xEA265C, 0x3C8275, 0xFFFFE4, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFF],
        CURVE_Gx: [0x1AACB1, 0xEE1EB2, 0x3ABC52, 0x3D4C7, 0x579B09, 0xCB0983, 0xA04F42, 0x297A95, 0xAADB61, 0xD6B65A, 0xBC9E],
        CURVE_Gy: [0x84DE9F, 0xB9CB21, 0xBB80B5, 0x15310F, 0x55C3D1, 0xE035C9, 0xF77E04, 0x73448B, 0x99B6A6, 0xC0F133, 0xD08F],


    };
    return ROM_CURVE_NUMS256W;
};

ROM_CURVE_NUMS384E = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_NUMS384E = {

        // NUMS384E Curve
        CURVE_A: 1,
        CURVE_B_I: -11556,
        CURVE_B: [0x7FD19F, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0xFFFF],
        CURVE_Order: [0x23897D, 0x3989CD, 0x6482E7, 0x59AE43, 0x4555AA, 0x39EC3C, 0x2D1AF8, 0x238D0E, 0x7FFFE2, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3FFF],
        CURVE_Gx: [0x206BDE, 0x1C8D8, 0x4D4355, 0x2A2CA0, 0x292B16, 0x680DFE, 0x3CCC58, 0x31FFD4, 0x4C0057, 0xDCB7C, 0x4C2FD1, 0x2AEDAD, 0x2129AE, 0x1816D4, 0x6A499B, 0x8FDA2, 0x61B1],
        CURVE_Gy: [0x729392, 0x7C3E0, 0x727634, 0x376246, 0x2B0F94, 0x49600E, 0x7D9165, 0x7CC7B, 0x5F5683, 0x69E284, 0x5AB609, 0x86EB8, 0x1A423B, 0x10E716, 0x69BBAC, 0x1F33DC, 0x8298],

    };
    return ROM_CURVE_NUMS384E;
};

ROM_CURVE_NUMS384W = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_NUMS384W = {

        // NUMS384W Curve
        CURVE_A: -3,
        CURVE_B_I: -34568,
        CURVE_B: [0x7F77BB, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0xFFFF],
        CURVE_Order: [0xE61B9, 0x3ECF6, 0x698136, 0x61BF13, 0x29D3D4, 0x1037DB, 0x3AD75A, 0xF578F, 0x7FFFD6, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0xFFFF],
        CURVE_Gx: [0x18152A, 0x740841, 0x6FAE72, 0x7B0E23, 0x6ED100, 0x684A45, 0x4A9B31, 0x5E948D, 0x79F4F3, 0x1BF703, 0x89707, 0x2F8D30, 0x222410, 0x91019, 0x5BC607, 0x2B7858, 0x7579],
        CURVE_Gy: [0x180716, 0x71D8CC, 0x1971D2, 0x7FA569, 0x6B4DBB, 0x6FD79A, 0x4486A0, 0x1041BE, 0x739CB9, 0x6FF0FE, 0x4011A5, 0x267BF5, 0x530058, 0x1AFC67, 0x66E38E, 0x71B470, 0xACDE],


    };
    return ROM_CURVE_NUMS384W;
};

ROM_CURVE_NUMS512E = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_NUMS512E = {

        // NUMS512E Curve
        CURVE_A: 1,
        CURVE_B_I: -78296,
        CURVE_B: [0x7ECBEF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F],
        CURVE_Order: [0x6ED46D, 0x19EA37, 0x7D9D1A, 0x6F7F67, 0x605786, 0x5EA548, 0x5C2DA1, 0x1FEC64, 0x11BA9E, 0x5A5F9F, 0x53C18D, 0x7FFFFD, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0xF],
        CURVE_Gx: [0x6C57FE, 0x565333, 0x5716E6, 0x662780, 0x525427, 0x15A1FC, 0x15A241, 0x5EE4C9, 0x730F78, 0x1DDC8C, 0x188705, 0x5C0A3A, 0x6BE273, 0x44F42F, 0x7128E0, 0x73CFA6, 0x332FD1, 0x11A78A, 0x632DE2, 0x34E3D0, 0x5128DB, 0x71C62D, 0x37],
        CURVE_Gy: [0x62F5E1, 0x3D8183, 0x7CC9B7, 0x5F8E80, 0x6D38A9, 0x3FA04C, 0xABB30, 0xD0343, 0x356260, 0x65D32C, 0x3294F, 0x741A09, 0x395909, 0x55256D, 0x96748, 0x7B936C, 0x6EE476, 0x50544A, 0x43D5DE, 0x538CC5, 0x39D49C, 0x2137FE, 0x1B],

    };
    return ROM_CURVE_NUMS512E;
};

ROM_CURVE_NUMS512W = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_CURVE_NUMS512W = {

        // NUMS512W Curve
        CURVE_A: -3,
        CURVE_B_I: 121243,
        CURVE_B: [0x1D99B, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        CURVE_Order: [0x33555D, 0x7E7208, 0xF3854, 0x3E692, 0x68B366, 0x38C76A, 0x65F42F, 0x612C76, 0x31B4F, 0x7729CF, 0x6CF293, 0x7FFFFA, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F],
        CURVE_Gx: [0x2BAE57, 0xF2B19, 0xB720A, 0x6B7AEF, 0x560137, 0x3063AB, 0x95585, 0x3CA143, 0x359E93, 0x220ED6, 0x408685, 0x36CFCA, 0xC2530, 0x28A0DC, 0x407DA1, 0x6C1DDA, 0x5298CA, 0x407A76, 0x2DC00A, 0x549ED1, 0x7141D0, 0x580688, 0xE],
        CURVE_Gy: [0x3527A6, 0xEC070, 0x248E82, 0x67E87F, 0x35C1E4, 0x4059E5, 0x2C9695, 0x10D420, 0x6DE9C1, 0x35161D, 0xA1057, 0xA78A5, 0x60C7BD, 0x11E964, 0x6F2EE3, 0x6DEF55, 0x4B97, 0x47D762, 0x3BBB71, 0x359E70, 0x229AD5, 0x74A99, 0x25],

    };
    return ROM_CURVE_NUMS512W;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = {
        ROM_CURVE_ANSSI: ROM_CURVE_ANSSI,
        ROM_CURVE_BLS383: ROM_CURVE_BLS383,
        ROM_CURVE_BLS461: ROM_CURVE_BLS461,
        ROM_CURVE_FP256BN: ROM_CURVE_FP256BN,
        ROM_CURVE_FP512BN: ROM_CURVE_FP512BN,
        ROM_CURVE_BN254: ROM_CURVE_BN254,
        ROM_CURVE_BN254CX: ROM_CURVE_BN254CX,
        ROM_CURVE_BRAINPOOL: ROM_CURVE_BRAINPOOL,
        ROM_CURVE_C25519: ROM_CURVE_C25519,
        ROM_CURVE_C41417: ROM_CURVE_C41417,
        ROM_CURVE_ED25519: ROM_CURVE_ED25519,
        ROM_CURVE_GOLDILOCKS: ROM_CURVE_GOLDILOCKS,
        ROM_CURVE_HIFIVE: ROM_CURVE_HIFIVE,
        ROM_CURVE_NIST256: ROM_CURVE_NIST256,
        ROM_CURVE_NIST384: ROM_CURVE_NIST384,
        ROM_CURVE_NIST521: ROM_CURVE_NIST521,
        ROM_CURVE_NUMS256E: ROM_CURVE_NUMS256E,
        ROM_CURVE_NUMS256W: ROM_CURVE_NUMS256W,
        ROM_CURVE_NUMS384E: ROM_CURVE_NUMS384E,
        ROM_CURVE_NUMS384W: ROM_CURVE_NUMS384W,
        ROM_CURVE_NUMS512E: ROM_CURVE_NUMS512E,
        ROM_CURVE_NUMS512W: ROM_CURVE_NUMS512W
    };
}

},{}],"./rom_field":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* Fixed Data in ROM - Field and Curve parameters */

var ROM_FIELD_25519,
    ROM_FIELD_256PM,
    ROM_FIELD_384PM,
    ROM_FIELD_512PM,
    ROM_FIELD_ANSSI,
    ROM_FIELD_BLS383,
    ROM_FIELD_BLS461,
    ROM_FIELD_FP256BN,
    ROM_FIELD_FP512BN,
    ROM_FIELD_BN254,
    ROM_FIELD_BN254CX,
    ROM_FIELD_BRAINPOOL,
    ROM_FIELD_C41417,
    ROM_FIELD_GOLDILOCKS,
    ROM_FIELD_HIFIVE,
    ROM_FIELD_NIST256,
    ROM_FIELD_NIST384,
    ROM_FIELD_NIST521;

ROM_FIELD_25519 = function() {

    var ROM_FIELD_25519 = {

        // 25519 Curve Modulus
        Modulus: [0xFFFFED, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x7FFF],
        R2modp: [0xA40000, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        MConst: 0x13,

    };
    return ROM_FIELD_25519;
};

ROM_FIELD_256PM = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_FIELD_256PM = {

        // NUMS256 Curve Modulus
        // Base Bits= 24
        Modulus: [0xFFFF43, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFF],
        R2modp: [0x890000, 0x8B, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        MConst: 0xBD,

    };
    return ROM_FIELD_256PM;
};

ROM_FIELD_384PM = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_FIELD_384PM = {

        // NUMS384 Curve Modulus
        // Base Bits= 23
        Modulus: [0x7FFEC3, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0xFFFF],
        R2modp: [0x224000, 0xC4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        MConst: 0x13D,

    };
    return ROM_FIELD_384PM;
};

ROM_FIELD_512PM = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_FIELD_512PM = {

        // NUMS512 Curve Modulus
        // Base Bits= 23
        Modulus: [0x7FFDC7, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F],
        R2modp: [0x0, 0x58800, 0x4F, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        MConst: 0x239,

    };
    return ROM_FIELD_512PM;
};

ROM_FIELD_ANSSI = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_FIELD_ANSSI = {

        // ANSSI modulus
        // Base Bits= 24
        Modulus: [0x6E9C03, 0xF353D8, 0x6DE8FC, 0xABC8CA, 0x61ADBC, 0x435B39, 0xE8CE42, 0x10126D, 0x3AD58F, 0x178C0B, 0xF1FD],
        R2modp: [0xACECE3, 0x924166, 0xB10FCE, 0x6CFBB6, 0x87EC2, 0x3DE43D, 0xD2CF67, 0xA67DDE, 0xAD30F2, 0xBCAAE, 0xDF98],
        MConst: 0x4E1155,

    };
    return ROM_FIELD_ANSSI;
};

ROM_FIELD_BLS383 = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_FIELD_BLS383 = {

        // BLS383 Modulus
        // Base Bits= 23
        Modulus: [0x2D556B, 0x556A55, 0x75EAB2, 0x23AFBA, 0x1BB01, 0x2BAEA4, 0x5CC20F, 0x758B67, 0x20F99, 0x640A63, 0x69A3A8, 0x6009AA, 0x2A7852, 0x20B8AA, 0x7DD718, 0x104054, 0x7AC5],
        R2modp: [0x3353B, 0x66C8A7, 0x51A94C, 0x31E097, 0x340361, 0x5EBDB7, 0x3B6484, 0x3C1977, 0x73CD0B, 0x3C91A6, 0x269561, 0x1EC635, 0x182E9D, 0x5C56A2, 0x778340, 0x321B03, 0x5892],
        MConst: 0x23D0BD,
        Fra: [0x34508B, 0x4B3525, 0x4D0CAE, 0x503777, 0x463DB7, 0x3BF78E, 0xD072C, 0x2AE9A0, 0x69D32D, 0x282C73, 0x1730DB, 0xCD9F8, 0x6AB98B, 0x7DC9B0, 0x1CBCC8, 0x7D8CC3, 0x5A5],
        Frb: [0x7904E0, 0xA352F, 0x28DE04, 0x537843, 0x3B7D49, 0x6FB715, 0x4FBAE2, 0x4AA1C7, 0x183C6C, 0x3BDDEF, 0x5272CD, 0x532FB2, 0x3FBEC7, 0x22EEF9, 0x611A4F, 0x12B391, 0x751F],

    };

    return ROM_FIELD_BLS383;
};

ROM_FIELD_BLS461 = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_FIELD_BLS461 = {

        // BLS461 Modulus
        // Base Bits= 23
        Modulus: [0x2AAAAB, 0x155, 0x2AAAB0, 0x2AAA55, 0x55, 0x80004, 0x555FC0, 0x135548, 0x1CC00F, 0x3FF4B8, 0x2D0AA3, 0x58A424, 0x2CCA47, 0x465B17, 0x6F5BC7, 0xA49AF, 0x55D694, 0x34AAB4, 0x155535, 0x2AAAAA, 0x1],
        R2modp: [0x621498, 0x3B585F, 0x41688, 0x6F780D, 0x17C239, 0x158D8A, 0x491A92, 0x737DF1, 0x22A06, 0x460263, 0x275FF2, 0x5496C3, 0x6D4AD2, 0x3A7B46, 0x3A6323, 0x1723B1, 0x76204B, 0x66FD26, 0x4E743E, 0x1BE66E, 0x0],
        MConst: 0x7FFFFD,
        Fra: [0x12A3A, 0x2F7F37, 0x3DC4, 0x52CCE2, 0x1C6308, 0xB7F14, 0x4381D4, 0x52D328, 0x58D45F, 0x359C90, 0x1DC2CC, 0x616582, 0x7C61EB, 0x6B11C5, 0x64341C, 0x421B30, 0x4DFEFA, 0x3CABC4, 0x12DFDA, 0x172028, 0x1],
        Frb: [0x298071, 0x50821E, 0x2A6CEB, 0x57DD73, 0x639D4C, 0x7C80EF, 0x11DDEB, 0x408220, 0x43EBAF, 0xA5827, 0xF47D7, 0x773EA2, 0x30685B, 0x5B4951, 0xB27AA, 0x482E7F, 0x7D799, 0x77FEF0, 0x2755A, 0x138A82, 0x0],

    };

    return ROM_FIELD_BLS461;
};


ROM_FIELD_FP256BN = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_FIELD_FP256BN = {

        // FP256BN Modulus
        // Base Bits= 24
        Modulus: [0xD33013, 0x2DDBAE, 0x82D329, 0x12980A, 0xDC65FB, 0xA49F0C, 0x5EEE71, 0x46E5F2, 0xFCF0CD, 0xFFFFFF, 0xFFFF],
        R2modp: [0x2F4801, 0xF779D1, 0x3E7F6E, 0xB42A3A, 0xC919C9, 0xC26C08, 0x1BB715, 0xCA2ED6, 0x54293E, 0xE578E, 0x78EA],
        MConst: 0x37E5E5,
        Fra: [0x943106, 0x328AF, 0x8F7476, 0x1E3AB2, 0xA17151, 0x67CF39, 0x8DDB08, 0x2D1A6E, 0x786F35, 0x7662CA, 0x3D61],
        Frb: [0x3EFF0D, 0x2AB2FF, 0xF35EB3, 0xF45D57, 0x3AF4A9, 0x3CCFD3, 0xD11369, 0x19CB83, 0x848198, 0x899D35, 0xC29E],
    };

    return ROM_FIELD_FP256BN;
};

ROM_FIELD_FP512BN = function() {

    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_FIELD_FP512BN = {

        // FP512BN Modulus
        // Base Bits= 23
        Modulus: [0x2DEF33, 0x501245, 0x1ED3AC, 0x7A6323, 0x255CE5, 0x7C322D, 0x2AC8DB, 0x4632EF, 0x18B8E4, 0x3D597D, 0x451B3C, 0x77A2A, 0x3C111B, 0x78177C, 0x32D4C1, 0x5D0EC, 0x7F01C6, 0x7FF3D8, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3F],
        R2modp: [0x23E65D, 0x575A37, 0x411CD0, 0x295FB3, 0x640669, 0x375C69, 0x92395, 0x738492, 0x780D6D, 0x1BCD9D, 0x417CAA, 0x2DC6FB, 0x7EACFB, 0x327043, 0x7F2FC7, 0xF268C, 0x73D733, 0x2147C9, 0x2ACCD3, 0x32EAF8, 0x3B2C1E, 0xD46A2, 0x30],
        MConst: 0x4C5C05,
        Fra: [0x373AB2, 0x2F63E9, 0x47D258, 0x101576, 0x1514F6, 0x503C2E, 0x34EF61, 0x4FB040, 0x2CBBB5, 0x553D0A, 0x63A7E2, 0x10341C, 0x48CF2E, 0x3564D7, 0x25BDE4, 0x50C529, 0x468B4E, 0x2D518F, 0x6DE46, 0x7C84AD, 0x1CF5BB, 0x5EE355, 0x7],
        Frb: [0x76B481, 0x20AE5B, 0x570154, 0x6A4DAC, 0x1047EF, 0x2BF5FF, 0x75D97A, 0x7682AE, 0x6BFD2E, 0x681C72, 0x617359, 0x77460D, 0x7341EC, 0x42B2A4, 0xD16DD, 0x350BC3, 0x387677, 0x52A249, 0x7921B9, 0x37B52, 0x630A44, 0x211CAA, 0x38],

    };

    return ROM_FIELD_FP512BN;
};


ROM_FIELD_BN254 = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_FIELD_BN254 = {

        // BN254 Modulus
        // Base Bits= 24
        Modulus: [0x13, 0x0, 0x13A700, 0x0, 0x210000, 0x861, 0x800000, 0xBA344D, 0x1, 0x648240, 0x2523],
        R2modp: [0x2F2AA7, 0x537047, 0xF8F174, 0xC3E364, 0xAB8C1C, 0x3C2035, 0x69549, 0x379287, 0x3BE629, 0x75617A, 0x1F47],
        MConst: 0x9435E5,
        Fra: [0x2A6DE9, 0xE6C06F, 0xC2E17D, 0x4D3F77, 0x97492, 0x953F85, 0x50A846, 0xB6499B, 0x2E7C8C, 0x761921, 0x1B37],
        Frb: [0xD5922A, 0x193F90, 0x50C582, 0xB2C088, 0x178B6D, 0x6AC8DC, 0x2F57B9, 0x3EAB2, 0xD18375, 0xEE691E, 0x9EB],

    };

    return ROM_FIELD_BN254;
};

ROM_FIELD_BN254CX = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_FIELD_BN254CX = {

        // BN254CX Modulus
        // Base Bits= 24
        Modulus: [0x1B55B3, 0x23EF5C, 0xE1BE66, 0x18093E, 0x3FD6EE, 0x66D324, 0x647A63, 0xB0BDDF, 0x702A0D, 0x8, 0x2400],
        R2modp: [0x8EE63D, 0x721FDE, 0xCC0891, 0x10C28B, 0xD4F5A, 0x4C18FB, 0x9036FA, 0x3F845F, 0xA507E4, 0x78EB29, 0x1587],
        MConst: 0x789E85,
        Fra: [0xC80EA3, 0x83355, 0x215BD9, 0xF173F8, 0x677326, 0x189868, 0x8AACA7, 0xAFE18B, 0x3A0164, 0x82FA6, 0x1359],
        Frb: [0x534710, 0x1BBC06, 0xC0628D, 0x269546, 0xD863C7, 0x4E3ABB, 0xD9CDBC, 0xDC53, 0x3628A9, 0xF7D062, 0x10A6],
    };

    return ROM_FIELD_BN254CX;
};

ROM_FIELD_BRAINPOOL = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_FIELD_BRAINPOOL = {

        // Brainpool modulus
        // Base Bits= 24
        Modulus: [0x6E5377, 0x481D1F, 0x282013, 0xD52620, 0x3BF623, 0x8D726E, 0x909D83, 0x3E660A, 0xEEA9BC, 0x57DBA1, 0xA9FB],
        R2modp: [0x35B819, 0xB03428, 0xECAF0F, 0x3854A4, 0x4A0ED5, 0x2421EA, 0xAA562C, 0xF9C45, 0xDDAE58, 0x4350FD, 0x52B8],
        MConst: 0xFD89B9,

    };
    return ROM_FIELD_BRAINPOOL;
};

ROM_FIELD_C41417 = function() {
    /* Fixed Data in ROM - Field and Curve parameters */


    var ROM_FIELD_C41417 = {

        // C41417 modulus
        // Base Bits= 2
        Modulus: [0x3FFFEF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFF],
        R2modp: [0x12100, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        MConst: 0x11,
    };
    return ROM_FIELD_C41417;
};

ROM_FIELD_GOLDILOCKS = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_FIELD_GOLDILOCKS = {

        // GOLDILOCKS modulus
        // Base Bits= 23
        Modulus: [0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7DFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FF],
        R2modp: [0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xC0000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        MConst: 0x1,
    };
    return ROM_FIELD_GOLDILOCKS;
};

ROM_FIELD_HIFIVE = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_FIELD_HIFIVE = {

        // HIFIVE modulus
        // Base Bits= 23
        Modulus: [0x7FFFFD, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x3FFF],
        R2modp: [0x240000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        MConst: 0x3,
    };
    return ROM_FIELD_HIFIVE;
};

ROM_FIELD_NIST256 = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_FIELD_NIST256 = {

        // NIST256 Modulus
        // Base Bits= 24
        Modulus: [0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0x0, 0x0, 0x0, 0x0, 0x1, 0xFFFF00, 0xFFFF],
        R2modp: [0x30000, 0x0, 0x0, 0xFFFF00, 0xFBFFFF, 0xFFFFFF, 0xFFFFFE, 0xFFFFFF, 0xFDFFFF, 0xFFFFFF, 0x4],
        MConst: 0x1,

    };
    return ROM_FIELD_NIST256;
};

ROM_FIELD_NIST384 = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_FIELD_NIST384 = {

        // NIST384 modulus
        // Base Bits= 23
        Modulus: [0x7FFFFF, 0x1FF, 0x0, 0x0, 0x7FFFF0, 0x7FDFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0xFFFF],
        R2modp: [0x4000, 0x0, 0x7FFFFE, 0x1FF, 0x80000, 0x0, 0x0, 0x7FC000, 0x3FFFFF, 0x0, 0x200, 0x20000, 0x0, 0x0, 0x0, 0x0, 0x0],
        MConst: 0x1,

    };
    return ROM_FIELD_NIST384;
};

ROM_FIELD_NIST521 = function() {
    /* Fixed Data in ROM - Field and Curve parameters */

    var ROM_FIELD_NIST521 = {

        // NIST521 modulus
        // Base Bits= 23
        Modulus: [0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFFFF, 0x7FFF],
        R2modp: [0x10000, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        MConst: 0x1,
    };
    return ROM_FIELD_NIST521;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = {
        ROM_FIELD_25519: ROM_FIELD_25519,
        ROM_FIELD_256PM: ROM_FIELD_256PM,
        ROM_FIELD_384PM: ROM_FIELD_384PM,
        ROM_FIELD_512PM: ROM_FIELD_512PM,
        ROM_FIELD_ANSSI: ROM_FIELD_ANSSI,
        ROM_FIELD_BLS383: ROM_FIELD_BLS383,
        ROM_FIELD_BLS461: ROM_FIELD_BLS461,
        ROM_FIELD_FP256BN: ROM_FIELD_FP256BN,
        ROM_FIELD_FP512BN: ROM_FIELD_FP512BN,
        ROM_FIELD_BN254: ROM_FIELD_BN254,
        ROM_FIELD_BN254CX: ROM_FIELD_BN254CX,
        ROM_FIELD_BRAINPOOL: ROM_FIELD_BRAINPOOL,
        ROM_FIELD_C41417: ROM_FIELD_C41417,
        ROM_FIELD_GOLDILOCKS: ROM_FIELD_GOLDILOCKS,
        ROM_FIELD_HIFIVE: ROM_FIELD_HIFIVE,
        ROM_FIELD_NIST256: ROM_FIELD_NIST256,
        ROM_FIELD_NIST384: ROM_FIELD_NIST384,
        ROM_FIELD_NIST521: ROM_FIELD_NIST521,
    };
}

},{}],"./rsa":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* RSA API Functions */

var RSA,
    rsa_private_key,
    rsa_public_key;

RSA = function(ctx) {
    "use strict";

    var RSA = {
        RFS: ctx.BIG.MODBYTES * ctx.FF.FFLEN,
        SHA256: 32,
        SHA384: 48,
        SHA512: 64,

        HASH_TYPE: 32,

        /* SHAXXX identifier strings */
        SHA256ID: [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20],
        SHA384ID: [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30],
        SHA512ID: [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40],

        bytestohex: function(b) {
            var s = "",
                len = b.length,
                ch, i;

            for (i = 0; i < len; i++) {
                ch = b[i];
                s += ((ch >>> 4) & 15).toString(16);
                s += (ch & 15).toString(16);

            }
            return s;
        },

        bytestostring: function(b) {
            var s = "",
                i;

            for (i = 0; i < b.length; i++) {
                s += String.fromCharCode(b[i]);
            }

            return s;
        },

        stringtobytes: function(s) {
            var b = [],
                i;

            for (i = 0; i < s.length; i++) {
                b.push(s.charCodeAt(i));
            }

            return b;
        },

        hashit: function(sha, A, n) {
            var R = [],
                H;

            if (sha == this.SHA256) {
                H = new ctx.HASH256();

                if (A != null) {
                    H.process_array(A);
                }

                if (n >= 0) {
                    H.process_num(n);
                }

                R = H.hash();
            } else if (sha == this.SHA384) {
                H = new ctx.HASH384();

                if (A != null) {
                    H.process_array(A);
                }

                if (n >= 0) {
                    H.process_num(n);
                }

                R = H.hash();
            } else if (sha == this.SHA512) {
                H = new ctx.HASH512();

                if (A != null) {
                    H.process_array(A);
                }

                if (n >= 0) {
                    H.process_num(n);
                }

                R = H.hash();
            }

            return R;
        },

        KEY_PAIR: function(rng, e, PRIV, PUB) { /* IEEE1363 A16.11/A16.12 more or less */
            var n = PUB.n.length >> 1,
                t = new ctx.FF(n),
                p1 = new ctx.FF(n),
                q1 = new ctx.FF(n);

            for (;;) {
                PRIV.p.random(rng);

                while (PRIV.p.lastbits(2) != 3) {
                    PRIV.p.inc(1);
                }

                while (!ctx.FF.prime(PRIV.p, rng)) {
                    PRIV.p.inc(4);
                }

                p1.copy(PRIV.p);
                p1.dec(1);

                if (p1.cfactor(e)) {
                    continue;
                }

                break;
            }

            for (;;) {
                PRIV.q.random(rng);

                while (PRIV.q.lastbits(2) != 3) {
                    PRIV.q.inc(1);
                }

                while (!ctx.FF.prime(PRIV.q, rng)) {
                    PRIV.q.inc(4);
                }

                q1.copy(PRIV.q);
                q1.dec(1);

                if (q1.cfactor(e)) {
                    continue;
                }

                break;
            }

            PUB.n = ctx.FF.mul(PRIV.p, PRIV.q);
            PUB.e = e;

            t.copy(p1);
            t.shr();
            PRIV.dp.set(e);
            PRIV.dp.invmodp(t);
            if (PRIV.dp.parity() === 0) {
                PRIV.dp.add(t);
            }
            PRIV.dp.norm();

            t.copy(q1);
            t.shr();
            PRIV.dq.set(e);
            PRIV.dq.invmodp(t);
            if (PRIV.dq.parity() === 0) {
                PRIV.dq.add(t);
            }
            PRIV.dq.norm();

            PRIV.c.copy(PRIV.p);
            PRIV.c.invmodp(PRIV.q);

            return;
        },

        /* Mask Generation Function */
        MGF1: function(sha, Z, olen, K) {
            var hlen = sha,
                B = [],
                k = 0,
                counter, cthreshold, i;

            for (i = 0; i < K.length; i++) {
                K[i] = 0;
            }

            cthreshold = Math.floor(olen / hlen);
            if (olen % hlen !== 0) {
                cthreshold++;
            }

            for (counter = 0; counter < cthreshold; counter++) {
                B = this.hashit(sha, Z, counter);

                if (k + hlen > olen) {
                    for (i = 0; i < olen % hlen; i++) {
                        K[k++] = B[i];
                    }
                } else {
                    for (i = 0; i < hlen; i++) {
                        K[k++] = B[i];
                    }
                }
            }
        },

        PKCS15: function(sha, m, w) {
            var olen = ctx.FF.FF_BITS / 8,
                hlen = sha,
                idlen = 19,
                H, i, j;

            if (olen < idlen + hlen + 10) {
                return false;
            }

            H = this.hashit(sha, m, -1);

            for (i = 0; i < w.length; i++) {
                w[i] = 0;
            }

            i = 0;
            w[i++] = 0;
            w[i++] = 1;
            for (j = 0; j < olen - idlen - hlen - 3; j++) {
                w[i++] = 0xFF;
            }
            w[i++] = 0;

            if (hlen == this.SHA256) {
                for (j = 0; j < idlen; j++) {
                    w[i++] = this.SHA256ID[j];
                }
            } else if (hlen == this.SHA384) {
                for (j = 0; j < idlen; j++) {
                    w[i++] = this.SHA384ID[j];
                }
            } else if (hlen == this.SHA512) {
                for (j = 0; j < idlen; j++) {
                    w[i++] = this.SHA512ID[j];
                }
            }

            for (j = 0; j < hlen; j++) {
                w[i++] = H[j];
            }

            return true;
        },

        /* OAEP Message Encoding for Encryption */
        OAEP_ENCODE: function(sha, m, rng, p) {
            var olen = RSA.RFS - 1,
                mlen = m.length,
                SEED = [],
                DBMASK = [],
                f = [],
                hlen,
                seedlen,
                slen,
                i, d, h;

            seedlen = hlen = sha;

            if (mlen > olen - hlen - seedlen - 1) {
                return null;
            }

            h = this.hashit(sha, p, -1);
            for (i = 0; i < hlen; i++) {
                f[i] = h[i];
            }

            slen = olen - mlen - hlen - seedlen - 1;

            for (i = 0; i < slen; i++) {
                f[hlen + i] = 0;
            }
            f[hlen + slen] = 1;
            for (i = 0; i < mlen; i++) {
                f[hlen + slen + 1 + i] = m[i];
            }

            for (i = 0; i < seedlen; i++) {
                SEED[i] = rng.getByte();
            }
            this.MGF1(sha, SEED, olen - seedlen, DBMASK);

            for (i = 0; i < olen - seedlen; i++) {
                DBMASK[i] ^= f[i];
            }
            this.MGF1(sha, DBMASK, seedlen, f);

            for (i = 0; i < seedlen; i++) {
                f[i] ^= SEED[i];
            }

            for (i = 0; i < olen - seedlen; i++) {
                f[i + seedlen] = DBMASK[i];
            }

            /* pad to length RFS */
            d = 1;
            for (i = RSA.RFS - 1; i >= d; i--) {
                f[i] = f[i - d];
            }
            for (i = d - 1; i >= 0; i--) {
                f[i] = 0;
            }

            return f;
        },

        /* OAEP Message Decoding for Decryption */
        OAEP_DECODE: function(sha, p, f) {
            var olen = RSA.RFS - 1,
                SEED = [],
                CHASH = [],
                DBMASK = [],
                comp,
                hlen,
                seedlen,
                x, t, d, i, k, h, r;

            seedlen = hlen = sha;

            if (olen < seedlen + hlen + 1) {
                return null;
            }

            for (i = 0; i < olen - seedlen; i++) {
                DBMASK[i] = 0;
            }

            if (f.length < RSA.RFS) {
                d = RSA.RFS - f.length;
                for (i = RSA.RFS - 1; i >= d; i--) {
                    f[i] = f[i - d];
                }
                for (i = d - 1; i >= 0; i--) {
                    f[i] = 0;
                }
            }

            h = this.hashit(sha, p, -1);
            for (i = 0; i < hlen; i++) {
                CHASH[i] = h[i];
            }

            x = f[0];

            for (i = seedlen; i < olen; i++) {
                DBMASK[i - seedlen] = f[i + 1];
            }

            this.MGF1(sha, DBMASK, seedlen, SEED);
            for (i = 0; i < seedlen; i++) {
                SEED[i] ^= f[i + 1];
            }
            this.MGF1(sha, SEED, olen - seedlen, f);
            for (i = 0; i < olen - seedlen; i++) {
                DBMASK[i] ^= f[i];
            }

            comp = true;
            for (i = 0; i < hlen; i++) {
                if (CHASH[i] != DBMASK[i]) {
                    comp = false;
                }
            }

            for (i = 0; i < olen - seedlen - hlen; i++) {
                DBMASK[i] = DBMASK[i + hlen];
            }

            for (i = 0; i < hlen; i++) {
                SEED[i] = CHASH[i] = 0;
            }

            for (k = 0;; k++) {
                if (k >= olen - seedlen - hlen) {
                    return null;
                }

                if (DBMASK[k] !== 0) {
                    break;
                }
            }

            t = DBMASK[k];

            if (!comp || x !== 0 || t != 0x01) {
                for (i = 0; i < olen - seedlen; i++) {
                    DBMASK[i] = 0;
                }
                return null;
            }

            r = [];

            for (i = 0; i < olen - seedlen - hlen - k - 1; i++) {
                r[i] = DBMASK[i + k + 1];
            }

            for (i = 0; i < olen - seedlen; i++) {
                DBMASK[i] = 0;
            }

            return r;
        },

        /* destroy the Private Key structure */
        PRIVATE_KEY_KILL: function(PRIV) {
            PRIV.p.zero();
            PRIV.q.zero();
            PRIV.dp.zero();
            PRIV.dq.zero();
            PRIV.c.zero();
        },

        /* RSA encryption with the public key */
        ENCRYPT: function(PUB, F, G) {
            var n = PUB.n.getlen(),
                f = new ctx.FF(n);

            ctx.FF.fromBytes(f, F);

            f.power(PUB.e, PUB.n);

            f.toBytes(G);
        },

        /* RSA decryption with the private key */
        DECRYPT: function(PRIV, G, F) {
            var n = PRIV.p.getlen(),
                g = new ctx.FF(2 * n),
                jp, jq, t;

            ctx.FF.fromBytes(g, G);

            jp = g.dmod(PRIV.p);
            jq = g.dmod(PRIV.q);

            jp.skpow(PRIV.dp, PRIV.p);
            jq.skpow(PRIV.dq, PRIV.q);

            g.zero();
            g.dscopy(jp);
            jp.mod(PRIV.q);
            if (ctx.FF.comp(jp, jq) > 0) {
                jq.add(PRIV.q);
            }
            jq.sub(jp);
            jq.norm();

            t = ctx.FF.mul(PRIV.c, jq);
            jq = t.dmod(PRIV.q);

            t = ctx.FF.mul(jq, PRIV.p);
            g.add(t);
            g.norm();

            g.toBytes(F);
        }
    };

    return RSA;
};

rsa_private_key = function(ctx) {
    "use strict";

    var rsa_private_key = function(n) {
        this.p = new ctx.FF(n);
        this.q = new ctx.FF(n);
        this.dp = new ctx.FF(n);
        this.dq = new ctx.FF(n);
        this.c = new ctx.FF(n);
    };

    return rsa_private_key;
};

rsa_public_key = function(ctx) {
    "use strict";

    var rsa_public_key = function(m) {
        this.e = 0;
        this.n = new ctx.FF(m);
    };

    return rsa_public_key;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = {
        RSA: RSA,
        rsa_public_key: rsa_public_key,
        rsa_private_key: rsa_private_key
    };
}

},{}],"./sha3":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/*
 * Implementation of the Secure Hashing Algorithm SHA-3

 * Generates a message digest. It should be impossible to come
 * come up with two messages that hash to the same value ("collision free").
 *
 * For use with byte-oriented messages only.
 */

var SHA3 = function(ctx) {
    "use strict";

    var SHA3 = function(olen) {
        this.length = 0;
        this.rate = 0;
        this.len = 0;
        this.S = [];
        this.init(olen);
    };

    SHA3.prototype = {

        transform: function() {
            var C = [],
                D = [],
                B = [],
                i, j, k;

            for (k = 0; k < SHA3.ROUNDS; k++) {
                C[0] = new ctx.UInt64(this.S[0][0].top ^ this.S[0][1].top ^ this.S[0][2].top ^ this.S[0][3].top ^ this.S[0][4].top, this.S[0][0].bot ^ this.S[0][1].bot ^ this.S[0][2].bot ^ this.S[0][3].bot ^ this.S[0][4].bot);
                C[1] = new ctx.UInt64(this.S[1][0].top ^ this.S[1][1].top ^ this.S[1][2].top ^ this.S[1][3].top ^ this.S[1][4].top, this.S[1][0].bot ^ this.S[1][1].bot ^ this.S[1][2].bot ^ this.S[1][3].bot ^ this.S[1][4].bot);
                C[2] = new ctx.UInt64(this.S[2][0].top ^ this.S[2][1].top ^ this.S[2][2].top ^ this.S[2][3].top ^ this.S[2][4].top, this.S[2][0].bot ^ this.S[2][1].bot ^ this.S[2][2].bot ^ this.S[2][3].bot ^ this.S[2][4].bot);
                C[3] = new ctx.UInt64(this.S[3][0].top ^ this.S[3][1].top ^ this.S[3][2].top ^ this.S[3][3].top ^ this.S[3][4].top, this.S[3][0].bot ^ this.S[3][1].bot ^ this.S[3][2].bot ^ this.S[3][3].bot ^ this.S[3][4].bot);
                C[4] = new ctx.UInt64(this.S[4][0].top ^ this.S[4][1].top ^ this.S[4][2].top ^ this.S[4][3].top ^ this.S[4][4].top, this.S[4][0].bot ^ this.S[4][1].bot ^ this.S[4][2].bot ^ this.S[4][3].bot ^ this.S[4][4].bot);

                D[0] = SHA3.xor(C[4], SHA3.rotl(C[1], 1));
                D[1] = SHA3.xor(C[0], SHA3.rotl(C[2], 1));
                D[2] = SHA3.xor(C[1], SHA3.rotl(C[3], 1));
                D[3] = SHA3.xor(C[2], SHA3.rotl(C[4], 1));
                D[4] = SHA3.xor(C[3], SHA3.rotl(C[0], 1));

                for (i = 0; i < 5; i++) {
                    B[i] = [];
                    for (j = 0; j < 5; j++) {
                        B[i][j] = new ctx.UInt64(0, 0);
                        this.S[i][j] = SHA3.xor(this.S[i][j], D[i]);
                    }
                }

                B[0][0] = this.S[0][0].copy();
                B[1][3] = SHA3.rotl(this.S[0][1], 36);
                B[2][1] = SHA3.rotl(this.S[0][2], 3);
                B[3][4] = SHA3.rotl(this.S[0][3], 41);
                B[4][2] = SHA3.rotl(this.S[0][4], 18);

                B[0][2] = SHA3.rotl(this.S[1][0], 1);
                B[1][0] = SHA3.rotl(this.S[1][1], 44);
                B[2][3] = SHA3.rotl(this.S[1][2], 10);
                B[3][1] = SHA3.rotl(this.S[1][3], 45);
                B[4][4] = SHA3.rotl(this.S[1][4], 2);

                B[0][4] = SHA3.rotl(this.S[2][0], 62);
                B[1][2] = SHA3.rotl(this.S[2][1], 6);
                B[2][0] = SHA3.rotl(this.S[2][2], 43);
                B[3][3] = SHA3.rotl(this.S[2][3], 15);
                B[4][1] = SHA3.rotl(this.S[2][4], 61);

                B[0][1] = SHA3.rotl(this.S[3][0], 28);
                B[1][4] = SHA3.rotl(this.S[3][1], 55);
                B[2][2] = SHA3.rotl(this.S[3][2], 25);
                B[3][0] = SHA3.rotl(this.S[3][3], 21);
                B[4][3] = SHA3.rotl(this.S[3][4], 56);

                B[0][3] = SHA3.rotl(this.S[4][0], 27);
                B[1][1] = SHA3.rotl(this.S[4][1], 20);
                B[2][4] = SHA3.rotl(this.S[4][2], 39);
                B[3][2] = SHA3.rotl(this.S[4][3], 8);
                B[4][0] = SHA3.rotl(this.S[4][4], 14);

                for (i = 0; i < 5; i++) {
                    for (j = 0; j < 5; j++) {
                        this.S[i][j] = SHA3.xor(B[i][j], SHA3.and(SHA3.not(B[(i + 1) % 5][j]), B[(i + 2) % 5][j]));
                    }
                }

                this.S[0][0] = SHA3.xor(this.S[0][0], SHA3.RC[k]);
            }
        },

        /* Initialise Hash function */
        init: function(olen) { /* initialise */
            var i, j;
            for (i = 0; i < 5; i++) {
                this.S[i] = [];
                for (j = 0; j < 5; j++) {
                    this.S[i][j] = new ctx.UInt64(0, 0);
                }
            }
            this.length = 0;
            this.len = olen;
            this.rate = 200 - 2 * olen;
        },

        /* process a single byte */
        process: function(byt) { /* process the next message byte */
            var i, j, k, b, cnt, el;

            cnt = (this.length % this.rate);
            b = cnt % 8;
            cnt >>= 3;
            i = cnt % 5;
            j = Math.floor(cnt / 5); /* process by columns! */

            el = new ctx.UInt64(0, byt);
            for (k = 0; k < b; k++) {
                el.shlb();
            }
            this.S[i][j] = SHA3.xor(this.S[i][j], el);

            this.length++;
            if ((this.length % this.rate) == 0) {
                this.transform();
            }
        },

        /* squeeze the sponge */
        squeeze: function(buff, olen) {
            var done,
                m = 0,
                i, j, k, el;

            /* extract by columns */
            done = false;

            for (;;) {
                for (j = 0; j < 5; j++) {
                    for (i = 0; i < 5; i++) {
                        el = this.S[i][j].copy();
                        for (k = 0; k < 8; k++) {
                            buff[m++] = (el.bot & 0xff);
                            if (m >= olen || (m % this.rate) == 0) {
                                done = true;
                                break;
                            }
                            el = SHA3.rotl(el, 56);
                        }

                        if (done) {
                            break;
                        }
                    }

                    if (done) {
                        break;
                    }
                }

                if (m >= olen) {
                    break;
                }

                done = false;
                this.transform();
            }
        },

        hash: function(buff) { /* pad message and finish - supply digest */
            var q = this.rate - (this.length % this.rate);
            if (q == 1) {
                this.process(0x86);
            } else {
                this.process(0x06); /* 0x06 for SHA-3 */
                while (this.length % this.rate != this.rate - 1) {
                    this.process(0x00);
                }
                this.process(0x80); /* this will force a final transform */
            }
            this.squeeze(buff, this.len);
        },

        shake: function(buff, olen) { /* pad message and finish - supply digest */
            var q = this.rate - (this.length % this.rate);
            if (q == 1) {
                this.process(0x9f);
            } else {
                this.process(0x1f); /* 0x06 for SHA-3 */
                while (this.length % this.rate != this.rate - 1) {
                    this.process(0x00);
                }
                this.process(0x80); /* this will force a final transform */
            }
            this.squeeze(buff, olen);
        }
    };

    /* static functions */
    SHA3.rotl = function(x, n) {
        if (n == 0) {
            return x;
        }

        if (n < 32) {
            return new ctx.UInt64((x.top << n) | (x.bot >>> (32 - n)), (x.bot << n) | (x.top >>> (32 - n)));
        } else {
            return new ctx.UInt64((x.bot << (n - 32)) | (x.top >>> (64 - n)), (x.top << (n - 32)) | (x.bot >>> (64 - n)));
        }
    };

    SHA3.xor = function(a, b) {
        return new ctx.UInt64(a.top ^ b.top, a.bot ^ b.bot);
    };

    SHA3.and = function(a, b) {
        return new ctx.UInt64(a.top & b.top, a.bot & b.bot);
    };

    SHA3.not = function(a) {
        return new ctx.UInt64(~a.top, ~a.bot);
    };

    /* constants */
    SHA3.ROUNDS = 24;
    SHA3.HASH224 = 28;
    SHA3.HASH256 = 32;
    SHA3.HASH384 = 48;
    SHA3.HASH512 = 64;
    SHA3.SHAKE128 = 16;
    SHA3.SHAKE256 = 32;

    SHA3.RC = [new ctx.UInt64(0x00000000, 0x00000001), new ctx.UInt64(0x00000000, 0x00008082),
        new ctx.UInt64(0x80000000, 0x0000808A), new ctx.UInt64(0x80000000, 0x80008000),
        new ctx.UInt64(0x00000000, 0x0000808B), new ctx.UInt64(0x00000000, 0x80000001),
        new ctx.UInt64(0x80000000, 0x80008081), new ctx.UInt64(0x80000000, 0x00008009),
        new ctx.UInt64(0x00000000, 0x0000008A), new ctx.UInt64(0x00000000, 0x00000088),
        new ctx.UInt64(0x00000000, 0x80008009), new ctx.UInt64(0x00000000, 0x8000000A),
        new ctx.UInt64(0x00000000, 0x8000808B), new ctx.UInt64(0x80000000, 0x0000008B),
        new ctx.UInt64(0x80000000, 0x00008089), new ctx.UInt64(0x80000000, 0x00008003),
        new ctx.UInt64(0x80000000, 0x00008002), new ctx.UInt64(0x80000000, 0x00000080),
        new ctx.UInt64(0x00000000, 0x0000800A), new ctx.UInt64(0x80000000, 0x8000000A),
        new ctx.UInt64(0x80000000, 0x80008081), new ctx.UInt64(0x80000000, 0x00008080),
        new ctx.UInt64(0x00000000, 0x80000001), new ctx.UInt64(0x80000000, 0x80008008),
    ];

    return SHA3;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports.SHA3 = SHA3;
}

},{}],"./uint64":[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/* rudimentary unsigned 64-bit type for SHA384 and SHA512 */

var UInt64 = function() {
    "use strict";

    var UInt64 = function(top, bot) {
        this.top = top;
        this.bot = bot;
    };

    UInt64.prototype = {
        add: function(y) {
            var t = (this.bot >>> 0) + (y.bot >>> 0),
                low = t >>> 0,
                high = (this.top >>> 0) + (y.top >>> 0);

            this.bot = low;

            if (low != t) {
                this.top = (high + 1) >>> 0;
            } else {
                this.top = high;
            }

            return this;
        },

        copy: function() {
            var r = new UInt64(this.top, this.bot);
            return r;
        },

        shlb: function() {
            var t = this.bot >>> 24;
            this.top = t + (this.top << 8);
            this.bot <<= 8;
            return this;
        }
    };

    return UInt64;
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports.UInt64 = UInt64;
}

},{}],1:[function(require,module,exports){
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

const SphinxParams = require("../../lib/SphinxParams");
const SC = require("../../lib/SphinxClient");
const sphinx_process = require("../../lib/SphinxNode").sphinx_process;

const bytesjs = require("bytes.js");
const r = 5;
const params = new SphinxParams();

let nodes_routing = [];
let node_priv_keys = [];
let node_pub_keys = [];

for(let i = 0; i < r; i++) {
    let nid = "node" + i;
    let x = params.group.gensecret();
    let y = params.group.expon(params.group.g, x);

    nodes_routing.push(SC.nenc(nid));
    node_priv_keys.push(x);
    node_pub_keys.push(y);
}

let dest = bytesjs.fromString("bob");
let message = bytesjs.fromString("this is a test");
let t0, t1;


console.log("Testing message encoding time");
let header, delta;
let bin_message;
t0 = Date.now();

for(let i = 0; i < 100; i++) {
    [header, delta] = SC.create_forward_message(params, nodes_routing, node_pub_keys, dest, message);
    bin_message = SC.pack_message(params, [header, delta]);
}

t1 = Date.now();
let avgTime = (t1 - t0) / 100;
let text = `Encoding took ${avgTime} milliseconds.`;
console.log(text);
let para = document.createElement("p");
let node = document.createTextNode(text);
para.appendChild(node);
document.body.appendChild(para);


console.log("Testing message processing time");
let x = node_priv_keys[0];
let lens = JSON.stringify([params.max_len, params.m]);
let param_dict = {};
param_dict[lens] = params;
t0 = Date.now();

for(let i = 0; i < 100; i++) {
    [header, delta] = SC.unpack_message(param_dict, params.ctx, bin_message)[1];
    sphinx_process(params, x, header, delta);
}

t1 = Date.now();
avgTime = (t1 - t0) / 100;
text = `Processing took ${avgTime} milliseconds.`;
console.log(text);
para = document.createElement("p");
node = document.createTextNode(text);
para.appendChild(node);
document.body.appendChild(para);
},{"../../lib/SphinxClient":5,"../../lib/SphinxNode":6,"../../lib/SphinxParams":7,"bytes.js":13}],2:[function(require,module,exports){
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
const Rand = require("../lib/Rand");

function Group_ECC() {
    // Group operations in ECC
    this.ctx = new CTX("NIST256");

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
    this.rng = new Rand();

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
        data = new Array(32 - data.length).fill(0).concat(data);
        let d = this.ctx.BIG.fromBytes(data);
        d.mod(this.order);
        return d;
    };

    this.printable = function(alpha) {
        let buf = [];
        alpha.toBytes(buf);
        return buf;
    };
}

module.exports = Group_ECC;
},{"../lib/Rand":4,"milagro-crypto-js":23}],3:[function(require,module,exports){
(function (Buffer){
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
}).call(this,require("buffer").Buffer)
},{"buffer":12,"msgpack5":25}],4:[function(require,module,exports){
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
},{"get-random-values":15}],5:[function(require,module,exports){
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

// A helper class to store PKI information.
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
},{"../lib/Packer":3,"assert":8,"get-random-values":15,"msgpack5":25}],6:[function(require,module,exports){
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
},{"assert":8}],7:[function(require,module,exports){
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

function SphinxParams(header_len = 192, body_len = 1024, assoc_len=0, k = 16) {
    this.assoc_len = assoc_len;
    this.max_len = header_len;
    this.m = body_len;
    this.k = k;
    this.group = new Group_ECC();
    this.ctx = this.group.ctx;

    /* Input is from an octet string M, output is to an octet string C.
       Output is truncated to the length of the input */
    this.aes_ctr = function(K, M, IV = null) {
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
    };

    this.lioness_enc = function(key, message) {
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
    };

    this.lioness_dec = function (key, message) {
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
    };

    // AES-CTR operation
    this.xor_rho = function(key, plain) {
        assert(key.length === this.k);
        return this.aes_ctr(key, plain);
    };

    // The HMAC; key is of length k, output is of length k
    this.mu = function(key, data) {
        assert(key.length === this.k);
        let ecdh = this.ctx.ECDH;
        let mac = new Array(this.k);
        ecdh.HMAC(ecdh.SHA256, data, key, mac);
        return mac;
    };

    // The PRP; key is of length k, data is of length m
    this.pi = function(key, data) {
        assert(key.length === this.k);
        assert(data.length === this.m);
        return this.lioness_enc(key, data);
    };

    // The inverse PRP; key is of length k, data is of length m
    this.pii = function(key, data) {
        assert(key.length === this.k);
        assert(data.length === this.m);
        return this.lioness_dec(key, data);
    };

    // The various hashes
    this.hash = function(data) {
        let H = new this.ctx.HASH256();
        H.process_array(data);
        return H.hash();
    };

    this.get_aes_key = function(s) {
        // [97, 101, 115, 95, 107, 101, 121, 58] = "aes_key:"
        return this.hash([97, 101, 115, 95, 107, 101, 121, 58].concat(this.group.printable(s))).slice(0, this.k);
    };

    this.derive_key = function(k, flavor) {
        assert(k.length === this.k);
        assert(flavor.length === this.k);
        let iv = flavor;
        let m = Array(this.k).fill(0);
        return this.aes_ctr(k, m, iv);
    };

    // "Compute a hash of alpha and s to use as a blinding factor"
    this.hb = function (k) {
        // "hbhbhbhbhbhbhbhb" = [104, 98, 104, 98, 104, 98, 104, 98, 104, 98, 104, 98, 104, 98, 104, 98]
        let K = this.derive_key(k, [104, 98, 104, 98, 104, 98, 104, 98, 104, 98, 104, 98, 104, 98, 104, 98]);
        return this.group.makeexp(K);
    };

    // "Compute a hash of s to use as a key for the PRG rho"
    this.hrho = function(k) {
        // "hrhohrhohrhohrho" = [104, 114, 104, 111, 104, 114, 104, 111, 104, 114, 104, 111, 104, 114, 104, 111]
        return this.derive_key(k, [104, 114, 104, 111, 104, 114, 104, 111, 104, 114, 104, 111, 104, 114, 104, 111]);
    };

    // "Compute a hash of s to use as a key for the HMAC mu"
    this.hmu = function(k) {
        // "hmu:hmu:hmu:hmu:" = [104, 109, 117, 58, 104, 109, 117, 58, 104, 109, 117, 58, 104, 109, 117, 58]
        return this.derive_key(k, [104, 109, 117, 58, 104, 109, 117, 58, 104, 109, 117, 58, 104, 109, 117, 58]);
    };

    // "Compute a hash of s to use as a key for the PRP pi"
    this.hpi = function(k) {
        // "hpi:hpi:hpi:hpi:" = [104, 112, 105, 58, 104, 112, 105, 58, 104, 112, 105, 58, 104, 112, 105, 58]
        return this.derive_key(k, [104, 112, 105, 58, 104, 112, 105, 58, 104, 112, 105, 58, 104, 112, 105, 58]);
    };

    // "Compute a hash of s to use to see if we've seen s before"
    this.htau = function(k) {
        // "htauhtauhtauhtau" = [104, 116, 97, 117, 104, 116, 97, 117, 104, 116, 97, 117, 104, 116, 97, 117]
        return this.derive_key(k, [104, 116, 97, 117, 104, 116, 97, 117, 104, 116, 97, 117, 104, 116, 97, 117]);
    };
}

module.exports = SphinxParams;
},{"../lib/Group_ECC":2,"assert":8}],8:[function(require,module,exports){
(function (global){
'use strict';

// compare and isBuffer taken from https://github.com/feross/buffer/blob/680e9e5e488f22aac27599a57dc844a6315928dd/index.js
// original notice:

/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <feross@feross.org> <http://feross.org>
 * @license  MIT
 */
function compare(a, b) {
  if (a === b) {
    return 0;
  }

  var x = a.length;
  var y = b.length;

  for (var i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i];
      y = b[i];
      break;
    }
  }

  if (x < y) {
    return -1;
  }
  if (y < x) {
    return 1;
  }
  return 0;
}
function isBuffer(b) {
  if (global.Buffer && typeof global.Buffer.isBuffer === 'function') {
    return global.Buffer.isBuffer(b);
  }
  return !!(b != null && b._isBuffer);
}

// based on node assert, original notice:

// http://wiki.commonjs.org/wiki/Unit_Testing/1.0
//
// THIS IS NOT TESTED NOR LIKELY TO WORK OUTSIDE V8!
//
// Originally from narwhal.js (http://narwhaljs.org)
// Copyright (c) 2009 Thomas Robinson <280north.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the 'Software'), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

var util = require('util/');
var hasOwn = Object.prototype.hasOwnProperty;
var pSlice = Array.prototype.slice;
var functionsHaveNames = (function () {
  return function foo() {}.name === 'foo';
}());
function pToString (obj) {
  return Object.prototype.toString.call(obj);
}
function isView(arrbuf) {
  if (isBuffer(arrbuf)) {
    return false;
  }
  if (typeof global.ArrayBuffer !== 'function') {
    return false;
  }
  if (typeof ArrayBuffer.isView === 'function') {
    return ArrayBuffer.isView(arrbuf);
  }
  if (!arrbuf) {
    return false;
  }
  if (arrbuf instanceof DataView) {
    return true;
  }
  if (arrbuf.buffer && arrbuf.buffer instanceof ArrayBuffer) {
    return true;
  }
  return false;
}
// 1. The assert module provides functions that throw
// AssertionError's when particular conditions are not met. The
// assert module must conform to the following interface.

var assert = module.exports = ok;

// 2. The AssertionError is defined in assert.
// new assert.AssertionError({ message: message,
//                             actual: actual,
//                             expected: expected })

var regex = /\s*function\s+([^\(\s]*)\s*/;
// based on https://github.com/ljharb/function.prototype.name/blob/adeeeec8bfcc6068b187d7d9fb3d5bb1d3a30899/implementation.js
function getName(func) {
  if (!util.isFunction(func)) {
    return;
  }
  if (functionsHaveNames) {
    return func.name;
  }
  var str = func.toString();
  var match = str.match(regex);
  return match && match[1];
}
assert.AssertionError = function AssertionError(options) {
  this.name = 'AssertionError';
  this.actual = options.actual;
  this.expected = options.expected;
  this.operator = options.operator;
  if (options.message) {
    this.message = options.message;
    this.generatedMessage = false;
  } else {
    this.message = getMessage(this);
    this.generatedMessage = true;
  }
  var stackStartFunction = options.stackStartFunction || fail;
  if (Error.captureStackTrace) {
    Error.captureStackTrace(this, stackStartFunction);
  } else {
    // non v8 browsers so we can have a stacktrace
    var err = new Error();
    if (err.stack) {
      var out = err.stack;

      // try to strip useless frames
      var fn_name = getName(stackStartFunction);
      var idx = out.indexOf('\n' + fn_name);
      if (idx >= 0) {
        // once we have located the function frame
        // we need to strip out everything before it (and its line)
        var next_line = out.indexOf('\n', idx + 1);
        out = out.substring(next_line + 1);
      }

      this.stack = out;
    }
  }
};

// assert.AssertionError instanceof Error
util.inherits(assert.AssertionError, Error);

function truncate(s, n) {
  if (typeof s === 'string') {
    return s.length < n ? s : s.slice(0, n);
  } else {
    return s;
  }
}
function inspect(something) {
  if (functionsHaveNames || !util.isFunction(something)) {
    return util.inspect(something);
  }
  var rawname = getName(something);
  var name = rawname ? ': ' + rawname : '';
  return '[Function' +  name + ']';
}
function getMessage(self) {
  return truncate(inspect(self.actual), 128) + ' ' +
         self.operator + ' ' +
         truncate(inspect(self.expected), 128);
}

// At present only the three keys mentioned above are used and
// understood by the spec. Implementations or sub modules can pass
// other keys to the AssertionError's constructor - they will be
// ignored.

// 3. All of the following functions must throw an AssertionError
// when a corresponding condition is not met, with a message that
// may be undefined if not provided.  All assertion methods provide
// both the actual and expected values to the assertion error for
// display purposes.

function fail(actual, expected, message, operator, stackStartFunction) {
  throw new assert.AssertionError({
    message: message,
    actual: actual,
    expected: expected,
    operator: operator,
    stackStartFunction: stackStartFunction
  });
}

// EXTENSION! allows for well behaved errors defined elsewhere.
assert.fail = fail;

// 4. Pure assertion tests whether a value is truthy, as determined
// by !!guard.
// assert.ok(guard, message_opt);
// This statement is equivalent to assert.equal(true, !!guard,
// message_opt);. To test strictly for the value true, use
// assert.strictEqual(true, guard, message_opt);.

function ok(value, message) {
  if (!value) fail(value, true, message, '==', assert.ok);
}
assert.ok = ok;

// 5. The equality assertion tests shallow, coercive equality with
// ==.
// assert.equal(actual, expected, message_opt);

assert.equal = function equal(actual, expected, message) {
  if (actual != expected) fail(actual, expected, message, '==', assert.equal);
};

// 6. The non-equality assertion tests for whether two objects are not equal
// with != assert.notEqual(actual, expected, message_opt);

assert.notEqual = function notEqual(actual, expected, message) {
  if (actual == expected) {
    fail(actual, expected, message, '!=', assert.notEqual);
  }
};

// 7. The equivalence assertion tests a deep equality relation.
// assert.deepEqual(actual, expected, message_opt);

assert.deepEqual = function deepEqual(actual, expected, message) {
  if (!_deepEqual(actual, expected, false)) {
    fail(actual, expected, message, 'deepEqual', assert.deepEqual);
  }
};

assert.deepStrictEqual = function deepStrictEqual(actual, expected, message) {
  if (!_deepEqual(actual, expected, true)) {
    fail(actual, expected, message, 'deepStrictEqual', assert.deepStrictEqual);
  }
};

function _deepEqual(actual, expected, strict, memos) {
  // 7.1. All identical values are equivalent, as determined by ===.
  if (actual === expected) {
    return true;
  } else if (isBuffer(actual) && isBuffer(expected)) {
    return compare(actual, expected) === 0;

  // 7.2. If the expected value is a Date object, the actual value is
  // equivalent if it is also a Date object that refers to the same time.
  } else if (util.isDate(actual) && util.isDate(expected)) {
    return actual.getTime() === expected.getTime();

  // 7.3 If the expected value is a RegExp object, the actual value is
  // equivalent if it is also a RegExp object with the same source and
  // properties (`global`, `multiline`, `lastIndex`, `ignoreCase`).
  } else if (util.isRegExp(actual) && util.isRegExp(expected)) {
    return actual.source === expected.source &&
           actual.global === expected.global &&
           actual.multiline === expected.multiline &&
           actual.lastIndex === expected.lastIndex &&
           actual.ignoreCase === expected.ignoreCase;

  // 7.4. Other pairs that do not both pass typeof value == 'object',
  // equivalence is determined by ==.
  } else if ((actual === null || typeof actual !== 'object') &&
             (expected === null || typeof expected !== 'object')) {
    return strict ? actual === expected : actual == expected;

  // If both values are instances of typed arrays, wrap their underlying
  // ArrayBuffers in a Buffer each to increase performance
  // This optimization requires the arrays to have the same type as checked by
  // Object.prototype.toString (aka pToString). Never perform binary
  // comparisons for Float*Arrays, though, since e.g. +0 === -0 but their
  // bit patterns are not identical.
  } else if (isView(actual) && isView(expected) &&
             pToString(actual) === pToString(expected) &&
             !(actual instanceof Float32Array ||
               actual instanceof Float64Array)) {
    return compare(new Uint8Array(actual.buffer),
                   new Uint8Array(expected.buffer)) === 0;

  // 7.5 For all other Object pairs, including Array objects, equivalence is
  // determined by having the same number of owned properties (as verified
  // with Object.prototype.hasOwnProperty.call), the same set of keys
  // (although not necessarily the same order), equivalent values for every
  // corresponding key, and an identical 'prototype' property. Note: this
  // accounts for both named and indexed properties on Arrays.
  } else if (isBuffer(actual) !== isBuffer(expected)) {
    return false;
  } else {
    memos = memos || {actual: [], expected: []};

    var actualIndex = memos.actual.indexOf(actual);
    if (actualIndex !== -1) {
      if (actualIndex === memos.expected.indexOf(expected)) {
        return true;
      }
    }

    memos.actual.push(actual);
    memos.expected.push(expected);

    return objEquiv(actual, expected, strict, memos);
  }
}

function isArguments(object) {
  return Object.prototype.toString.call(object) == '[object Arguments]';
}

function objEquiv(a, b, strict, actualVisitedObjects) {
  if (a === null || a === undefined || b === null || b === undefined)
    return false;
  // if one is a primitive, the other must be same
  if (util.isPrimitive(a) || util.isPrimitive(b))
    return a === b;
  if (strict && Object.getPrototypeOf(a) !== Object.getPrototypeOf(b))
    return false;
  var aIsArgs = isArguments(a);
  var bIsArgs = isArguments(b);
  if ((aIsArgs && !bIsArgs) || (!aIsArgs && bIsArgs))
    return false;
  if (aIsArgs) {
    a = pSlice.call(a);
    b = pSlice.call(b);
    return _deepEqual(a, b, strict);
  }
  var ka = objectKeys(a);
  var kb = objectKeys(b);
  var key, i;
  // having the same number of owned properties (keys incorporates
  // hasOwnProperty)
  if (ka.length !== kb.length)
    return false;
  //the same set of keys (although not necessarily the same order),
  ka.sort();
  kb.sort();
  //~~~cheap key test
  for (i = ka.length - 1; i >= 0; i--) {
    if (ka[i] !== kb[i])
      return false;
  }
  //equivalent values for every corresponding key, and
  //~~~possibly expensive deep test
  for (i = ka.length - 1; i >= 0; i--) {
    key = ka[i];
    if (!_deepEqual(a[key], b[key], strict, actualVisitedObjects))
      return false;
  }
  return true;
}

// 8. The non-equivalence assertion tests for any deep inequality.
// assert.notDeepEqual(actual, expected, message_opt);

assert.notDeepEqual = function notDeepEqual(actual, expected, message) {
  if (_deepEqual(actual, expected, false)) {
    fail(actual, expected, message, 'notDeepEqual', assert.notDeepEqual);
  }
};

assert.notDeepStrictEqual = notDeepStrictEqual;
function notDeepStrictEqual(actual, expected, message) {
  if (_deepEqual(actual, expected, true)) {
    fail(actual, expected, message, 'notDeepStrictEqual', notDeepStrictEqual);
  }
}


// 9. The strict equality assertion tests strict equality, as determined by ===.
// assert.strictEqual(actual, expected, message_opt);

assert.strictEqual = function strictEqual(actual, expected, message) {
  if (actual !== expected) {
    fail(actual, expected, message, '===', assert.strictEqual);
  }
};

// 10. The strict non-equality assertion tests for strict inequality, as
// determined by !==.  assert.notStrictEqual(actual, expected, message_opt);

assert.notStrictEqual = function notStrictEqual(actual, expected, message) {
  if (actual === expected) {
    fail(actual, expected, message, '!==', assert.notStrictEqual);
  }
};

function expectedException(actual, expected) {
  if (!actual || !expected) {
    return false;
  }

  if (Object.prototype.toString.call(expected) == '[object RegExp]') {
    return expected.test(actual);
  }

  try {
    if (actual instanceof expected) {
      return true;
    }
  } catch (e) {
    // Ignore.  The instanceof check doesn't work for arrow functions.
  }

  if (Error.isPrototypeOf(expected)) {
    return false;
  }

  return expected.call({}, actual) === true;
}

function _tryBlock(block) {
  var error;
  try {
    block();
  } catch (e) {
    error = e;
  }
  return error;
}

function _throws(shouldThrow, block, expected, message) {
  var actual;

  if (typeof block !== 'function') {
    throw new TypeError('"block" argument must be a function');
  }

  if (typeof expected === 'string') {
    message = expected;
    expected = null;
  }

  actual = _tryBlock(block);

  message = (expected && expected.name ? ' (' + expected.name + ').' : '.') +
            (message ? ' ' + message : '.');

  if (shouldThrow && !actual) {
    fail(actual, expected, 'Missing expected exception' + message);
  }

  var userProvidedMessage = typeof message === 'string';
  var isUnwantedException = !shouldThrow && util.isError(actual);
  var isUnexpectedException = !shouldThrow && actual && !expected;

  if ((isUnwantedException &&
      userProvidedMessage &&
      expectedException(actual, expected)) ||
      isUnexpectedException) {
    fail(actual, expected, 'Got unwanted exception' + message);
  }

  if ((shouldThrow && actual && expected &&
      !expectedException(actual, expected)) || (!shouldThrow && actual)) {
    throw actual;
  }
}

// 11. Expected to throw an error:
// assert.throws(block, Error_opt, message_opt);

assert.throws = function(block, /*optional*/error, /*optional*/message) {
  _throws(true, block, error, message);
};

// EXTENSION! This is annoying to write outside this module.
assert.doesNotThrow = function(block, /*optional*/error, /*optional*/message) {
  _throws(false, block, error, message);
};

assert.ifError = function(err) { if (err) throw err; };

var objectKeys = Object.keys || function (obj) {
  var keys = [];
  for (var key in obj) {
    if (hasOwn.call(obj, key)) keys.push(key);
  }
  return keys;
};

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"util/":45}],9:[function(require,module,exports){
'use strict'

exports.byteLength = byteLength
exports.toByteArray = toByteArray
exports.fromByteArray = fromByteArray

var lookup = []
var revLookup = []
var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array

var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
for (var i = 0, len = code.length; i < len; ++i) {
  lookup[i] = code[i]
  revLookup[code.charCodeAt(i)] = i
}

revLookup['-'.charCodeAt(0)] = 62
revLookup['_'.charCodeAt(0)] = 63

function placeHoldersCount (b64) {
  var len = b64.length
  if (len % 4 > 0) {
    throw new Error('Invalid string. Length must be a multiple of 4')
  }

  // the number of equal signs (place holders)
  // if there are two placeholders, than the two characters before it
  // represent one byte
  // if there is only one, then the three characters before it represent 2 bytes
  // this is just a cheap hack to not do indexOf twice
  return b64[len - 2] === '=' ? 2 : b64[len - 1] === '=' ? 1 : 0
}

function byteLength (b64) {
  // base64 is 4/3 + up to two characters of the original data
  return (b64.length * 3 / 4) - placeHoldersCount(b64)
}

function toByteArray (b64) {
  var i, l, tmp, placeHolders, arr
  var len = b64.length
  placeHolders = placeHoldersCount(b64)

  arr = new Arr((len * 3 / 4) - placeHolders)

  // if there are placeholders, only get up to the last complete 4 chars
  l = placeHolders > 0 ? len - 4 : len

  var L = 0

  for (i = 0; i < l; i += 4) {
    tmp = (revLookup[b64.charCodeAt(i)] << 18) | (revLookup[b64.charCodeAt(i + 1)] << 12) | (revLookup[b64.charCodeAt(i + 2)] << 6) | revLookup[b64.charCodeAt(i + 3)]
    arr[L++] = (tmp >> 16) & 0xFF
    arr[L++] = (tmp >> 8) & 0xFF
    arr[L++] = tmp & 0xFF
  }

  if (placeHolders === 2) {
    tmp = (revLookup[b64.charCodeAt(i)] << 2) | (revLookup[b64.charCodeAt(i + 1)] >> 4)
    arr[L++] = tmp & 0xFF
  } else if (placeHolders === 1) {
    tmp = (revLookup[b64.charCodeAt(i)] << 10) | (revLookup[b64.charCodeAt(i + 1)] << 4) | (revLookup[b64.charCodeAt(i + 2)] >> 2)
    arr[L++] = (tmp >> 8) & 0xFF
    arr[L++] = tmp & 0xFF
  }

  return arr
}

function tripletToBase64 (num) {
  return lookup[num >> 18 & 0x3F] + lookup[num >> 12 & 0x3F] + lookup[num >> 6 & 0x3F] + lookup[num & 0x3F]
}

function encodeChunk (uint8, start, end) {
  var tmp
  var output = []
  for (var i = start; i < end; i += 3) {
    tmp = (uint8[i] << 16) + (uint8[i + 1] << 8) + (uint8[i + 2])
    output.push(tripletToBase64(tmp))
  }
  return output.join('')
}

function fromByteArray (uint8) {
  var tmp
  var len = uint8.length
  var extraBytes = len % 3 // if we have 1 byte left, pad 2 bytes
  var output = ''
  var parts = []
  var maxChunkLength = 16383 // must be multiple of 3

  // go through the array every three bytes, we'll deal with trailing stuff later
  for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
    parts.push(encodeChunk(uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)))
  }

  // pad the end with zeros, but make sure to not forget the extra bytes
  if (extraBytes === 1) {
    tmp = uint8[len - 1]
    output += lookup[tmp >> 2]
    output += lookup[(tmp << 4) & 0x3F]
    output += '=='
  } else if (extraBytes === 2) {
    tmp = (uint8[len - 2] << 8) + (uint8[len - 1])
    output += lookup[tmp >> 10]
    output += lookup[(tmp >> 4) & 0x3F]
    output += lookup[(tmp << 2) & 0x3F]
    output += '='
  }

  parts.push(output)

  return parts.join('')
}

},{}],10:[function(require,module,exports){
(function (Buffer){
var DuplexStream = require('readable-stream/duplex')
  , util         = require('util')


function BufferList (callback) {
  if (!(this instanceof BufferList))
    return new BufferList(callback)

  this._bufs  = []
  this.length = 0

  if (typeof callback == 'function') {
    this._callback = callback

    var piper = function piper (err) {
      if (this._callback) {
        this._callback(err)
        this._callback = null
      }
    }.bind(this)

    this.on('pipe', function onPipe (src) {
      src.on('error', piper)
    })
    this.on('unpipe', function onUnpipe (src) {
      src.removeListener('error', piper)
    })
  } else {
    this.append(callback)
  }

  DuplexStream.call(this)
}


util.inherits(BufferList, DuplexStream)


BufferList.prototype._offset = function _offset (offset) {
  var tot = 0, i = 0, _t
  if (offset === 0) return [ 0, 0 ]
  for (; i < this._bufs.length; i++) {
    _t = tot + this._bufs[i].length
    if (offset < _t || i == this._bufs.length - 1)
      return [ i, offset - tot ]
    tot = _t
  }
}


BufferList.prototype.append = function append (buf) {
  var i = 0

  if (Buffer.isBuffer(buf)) {
    this._appendBuffer(buf);
  } else if (Array.isArray(buf)) {
    for (; i < buf.length; i++)
      this.append(buf[i])
  } else if (buf instanceof BufferList) {
    // unwrap argument into individual BufferLists
    for (; i < buf._bufs.length; i++)
      this.append(buf._bufs[i])
  } else if (buf != null) {
    // coerce number arguments to strings, since Buffer(number) does
    // uninitialized memory allocation
    if (typeof buf == 'number')
      buf = buf.toString()

    this._appendBuffer(new Buffer(buf));
  }

  return this
}


BufferList.prototype._appendBuffer = function appendBuffer (buf) {
  this._bufs.push(buf)
  this.length += buf.length
}


BufferList.prototype._write = function _write (buf, encoding, callback) {
  this._appendBuffer(buf)

  if (typeof callback == 'function')
    callback()
}


BufferList.prototype._read = function _read (size) {
  if (!this.length)
    return this.push(null)

  size = Math.min(size, this.length)
  this.push(this.slice(0, size))
  this.consume(size)
}


BufferList.prototype.end = function end (chunk) {
  DuplexStream.prototype.end.call(this, chunk)

  if (this._callback) {
    this._callback(null, this.slice())
    this._callback = null
  }
}


BufferList.prototype.get = function get (index) {
  return this.slice(index, index + 1)[0]
}


BufferList.prototype.slice = function slice (start, end) {
  if (typeof start == 'number' && start < 0)
    start += this.length
  if (typeof end == 'number' && end < 0)
    end += this.length
  return this.copy(null, 0, start, end)
}


BufferList.prototype.copy = function copy (dst, dstStart, srcStart, srcEnd) {
  if (typeof srcStart != 'number' || srcStart < 0)
    srcStart = 0
  if (typeof srcEnd != 'number' || srcEnd > this.length)
    srcEnd = this.length
  if (srcStart >= this.length)
    return dst || new Buffer(0)
  if (srcEnd <= 0)
    return dst || new Buffer(0)

  var copy   = !!dst
    , off    = this._offset(srcStart)
    , len    = srcEnd - srcStart
    , bytes  = len
    , bufoff = (copy && dstStart) || 0
    , start  = off[1]
    , l
    , i

  // copy/slice everything
  if (srcStart === 0 && srcEnd == this.length) {
    if (!copy) { // slice, but full concat if multiple buffers
      return this._bufs.length === 1
        ? this._bufs[0]
        : Buffer.concat(this._bufs, this.length)
    }

    // copy, need to copy individual buffers
    for (i = 0; i < this._bufs.length; i++) {
      this._bufs[i].copy(dst, bufoff)
      bufoff += this._bufs[i].length
    }

    return dst
  }

  // easy, cheap case where it's a subset of one of the buffers
  if (bytes <= this._bufs[off[0]].length - start) {
    return copy
      ? this._bufs[off[0]].copy(dst, dstStart, start, start + bytes)
      : this._bufs[off[0]].slice(start, start + bytes)
  }

  if (!copy) // a slice, we need something to copy in to
    dst = new Buffer(len)

  for (i = off[0]; i < this._bufs.length; i++) {
    l = this._bufs[i].length - start

    if (bytes > l) {
      this._bufs[i].copy(dst, bufoff, start)
    } else {
      this._bufs[i].copy(dst, bufoff, start, start + bytes)
      break
    }

    bufoff += l
    bytes -= l

    if (start)
      start = 0
  }

  return dst
}

BufferList.prototype.shallowSlice = function shallowSlice (start, end) {
  start = start || 0
  end = end || this.length

  if (start < 0)
    start += this.length
  if (end < 0)
    end += this.length

  var startOffset = this._offset(start)
    , endOffset = this._offset(end)
    , buffers = this._bufs.slice(startOffset[0], endOffset[0] + 1)

  if (endOffset[1] == 0)
    buffers.pop()
  else
    buffers[buffers.length-1] = buffers[buffers.length-1].slice(0, endOffset[1])

  if (startOffset[1] != 0)
    buffers[0] = buffers[0].slice(startOffset[1])

  return new BufferList(buffers)
}

BufferList.prototype.toString = function toString (encoding, start, end) {
  return this.slice(start, end).toString(encoding)
}

BufferList.prototype.consume = function consume (bytes) {
  while (this._bufs.length) {
    if (bytes >= this._bufs[0].length) {
      bytes -= this._bufs[0].length
      this.length -= this._bufs[0].length
      this._bufs.shift()
    } else {
      this._bufs[0] = this._bufs[0].slice(bytes)
      this.length -= bytes
      break
    }
  }
  return this
}


BufferList.prototype.duplicate = function duplicate () {
  var i = 0
    , copy = new BufferList()

  for (; i < this._bufs.length; i++)
    copy.append(this._bufs[i])

  return copy
}


BufferList.prototype.destroy = function destroy () {
  this._bufs.length = 0
  this.length = 0
  this.push(null)
}


;(function () {
  var methods = {
      'readDoubleBE' : 8
    , 'readDoubleLE' : 8
    , 'readFloatBE'  : 4
    , 'readFloatLE'  : 4
    , 'readInt32BE'  : 4
    , 'readInt32LE'  : 4
    , 'readUInt32BE' : 4
    , 'readUInt32LE' : 4
    , 'readInt16BE'  : 2
    , 'readInt16LE'  : 2
    , 'readUInt16BE' : 2
    , 'readUInt16LE' : 2
    , 'readInt8'     : 1
    , 'readUInt8'    : 1
  }

  for (var m in methods) {
    (function (m) {
      BufferList.prototype[m] = function (offset) {
        return this.slice(offset, offset + methods[m])[m](0)
      }
    }(m))
  }
}())


module.exports = BufferList

}).call(this,require("buffer").Buffer)
},{"buffer":12,"readable-stream/duplex":30,"util":45}],11:[function(require,module,exports){

},{}],12:[function(require,module,exports){
/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <https://feross.org>
 * @license  MIT
 */
/* eslint-disable no-proto */

'use strict'

var base64 = require('base64-js')
var ieee754 = require('ieee754')

exports.Buffer = Buffer
exports.SlowBuffer = SlowBuffer
exports.INSPECT_MAX_BYTES = 50

var K_MAX_LENGTH = 0x7fffffff
exports.kMaxLength = K_MAX_LENGTH

/**
 * If `Buffer.TYPED_ARRAY_SUPPORT`:
 *   === true    Use Uint8Array implementation (fastest)
 *   === false   Print warning and recommend using `buffer` v4.x which has an Object
 *               implementation (most compatible, even IE6)
 *
 * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
 * Opera 11.6+, iOS 4.2+.
 *
 * We report that the browser does not support typed arrays if the are not subclassable
 * using __proto__. Firefox 4-29 lacks support for adding new properties to `Uint8Array`
 * (See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438). IE 10 lacks support
 * for __proto__ and has a buggy typed array implementation.
 */
Buffer.TYPED_ARRAY_SUPPORT = typedArraySupport()

if (!Buffer.TYPED_ARRAY_SUPPORT && typeof console !== 'undefined' &&
    typeof console.error === 'function') {
  console.error(
    'This browser lacks typed array (Uint8Array) support which is required by ' +
    '`buffer` v5.x. Use `buffer` v4.x if you require old browser support.'
  )
}

function typedArraySupport () {
  // Can typed array instances can be augmented?
  try {
    var arr = new Uint8Array(1)
    arr.__proto__ = {__proto__: Uint8Array.prototype, foo: function () { return 42 }}
    return arr.foo() === 42
  } catch (e) {
    return false
  }
}

function createBuffer (length) {
  if (length > K_MAX_LENGTH) {
    throw new RangeError('Invalid typed array length')
  }
  // Return an augmented `Uint8Array` instance
  var buf = new Uint8Array(length)
  buf.__proto__ = Buffer.prototype
  return buf
}

/**
 * The Buffer constructor returns instances of `Uint8Array` that have their
 * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
 * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
 * and the `Uint8Array` methods. Square bracket notation works as expected -- it
 * returns a single octet.
 *
 * The `Uint8Array` prototype remains unmodified.
 */

function Buffer (arg, encodingOrOffset, length) {
  // Common case.
  if (typeof arg === 'number') {
    if (typeof encodingOrOffset === 'string') {
      throw new Error(
        'If encoding is specified then the first argument must be a string'
      )
    }
    return allocUnsafe(arg)
  }
  return from(arg, encodingOrOffset, length)
}

// Fix subarray() in ES2016. See: https://github.com/feross/buffer/pull/97
if (typeof Symbol !== 'undefined' && Symbol.species &&
    Buffer[Symbol.species] === Buffer) {
  Object.defineProperty(Buffer, Symbol.species, {
    value: null,
    configurable: true,
    enumerable: false,
    writable: false
  })
}

Buffer.poolSize = 8192 // not used by this implementation

function from (value, encodingOrOffset, length) {
  if (typeof value === 'number') {
    throw new TypeError('"value" argument must not be a number')
  }

  if (isArrayBuffer(value)) {
    return fromArrayBuffer(value, encodingOrOffset, length)
  }

  if (typeof value === 'string') {
    return fromString(value, encodingOrOffset)
  }

  return fromObject(value)
}

/**
 * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
 * if value is a number.
 * Buffer.from(str[, encoding])
 * Buffer.from(array)
 * Buffer.from(buffer)
 * Buffer.from(arrayBuffer[, byteOffset[, length]])
 **/
Buffer.from = function (value, encodingOrOffset, length) {
  return from(value, encodingOrOffset, length)
}

// Note: Change prototype *after* Buffer.from is defined to workaround Chrome bug:
// https://github.com/feross/buffer/pull/148
Buffer.prototype.__proto__ = Uint8Array.prototype
Buffer.__proto__ = Uint8Array

function assertSize (size) {
  if (typeof size !== 'number') {
    throw new TypeError('"size" argument must be a number')
  } else if (size < 0) {
    throw new RangeError('"size" argument must not be negative')
  }
}

function alloc (size, fill, encoding) {
  assertSize(size)
  if (size <= 0) {
    return createBuffer(size)
  }
  if (fill !== undefined) {
    // Only pay attention to encoding if it's a string. This
    // prevents accidentally sending in a number that would
    // be interpretted as a start offset.
    return typeof encoding === 'string'
      ? createBuffer(size).fill(fill, encoding)
      : createBuffer(size).fill(fill)
  }
  return createBuffer(size)
}

/**
 * Creates a new filled Buffer instance.
 * alloc(size[, fill[, encoding]])
 **/
Buffer.alloc = function (size, fill, encoding) {
  return alloc(size, fill, encoding)
}

function allocUnsafe (size) {
  assertSize(size)
  return createBuffer(size < 0 ? 0 : checked(size) | 0)
}

/**
 * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
 * */
Buffer.allocUnsafe = function (size) {
  return allocUnsafe(size)
}
/**
 * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
 */
Buffer.allocUnsafeSlow = function (size) {
  return allocUnsafe(size)
}

function fromString (string, encoding) {
  if (typeof encoding !== 'string' || encoding === '') {
    encoding = 'utf8'
  }

  if (!Buffer.isEncoding(encoding)) {
    throw new TypeError('"encoding" must be a valid string encoding')
  }

  var length = byteLength(string, encoding) | 0
  var buf = createBuffer(length)

  var actual = buf.write(string, encoding)

  if (actual !== length) {
    // Writing a hex string, for example, that contains invalid characters will
    // cause everything after the first invalid character to be ignored. (e.g.
    // 'abxxcd' will be treated as 'ab')
    buf = buf.slice(0, actual)
  }

  return buf
}

function fromArrayLike (array) {
  var length = array.length < 0 ? 0 : checked(array.length) | 0
  var buf = createBuffer(length)
  for (var i = 0; i < length; i += 1) {
    buf[i] = array[i] & 255
  }
  return buf
}

function fromArrayBuffer (array, byteOffset, length) {
  if (byteOffset < 0 || array.byteLength < byteOffset) {
    throw new RangeError('\'offset\' is out of bounds')
  }

  if (array.byteLength < byteOffset + (length || 0)) {
    throw new RangeError('\'length\' is out of bounds')
  }

  var buf
  if (byteOffset === undefined && length === undefined) {
    buf = new Uint8Array(array)
  } else if (length === undefined) {
    buf = new Uint8Array(array, byteOffset)
  } else {
    buf = new Uint8Array(array, byteOffset, length)
  }

  // Return an augmented `Uint8Array` instance
  buf.__proto__ = Buffer.prototype
  return buf
}

function fromObject (obj) {
  if (Buffer.isBuffer(obj)) {
    var len = checked(obj.length) | 0
    var buf = createBuffer(len)

    if (buf.length === 0) {
      return buf
    }

    obj.copy(buf, 0, 0, len)
    return buf
  }

  if (obj) {
    if (isArrayBufferView(obj) || 'length' in obj) {
      if (typeof obj.length !== 'number' || numberIsNaN(obj.length)) {
        return createBuffer(0)
      }
      return fromArrayLike(obj)
    }

    if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
      return fromArrayLike(obj.data)
    }
  }

  throw new TypeError('First argument must be a string, Buffer, ArrayBuffer, Array, or array-like object.')
}

function checked (length) {
  // Note: cannot use `length < K_MAX_LENGTH` here because that fails when
  // length is NaN (which is otherwise coerced to zero.)
  if (length >= K_MAX_LENGTH) {
    throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                         'size: 0x' + K_MAX_LENGTH.toString(16) + ' bytes')
  }
  return length | 0
}

function SlowBuffer (length) {
  if (+length != length) { // eslint-disable-line eqeqeq
    length = 0
  }
  return Buffer.alloc(+length)
}

Buffer.isBuffer = function isBuffer (b) {
  return b != null && b._isBuffer === true
}

Buffer.compare = function compare (a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError('Arguments must be Buffers')
  }

  if (a === b) return 0

  var x = a.length
  var y = b.length

  for (var i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i]
      y = b[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

Buffer.isEncoding = function isEncoding (encoding) {
  switch (String(encoding).toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'latin1':
    case 'binary':
    case 'base64':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return true
    default:
      return false
  }
}

Buffer.concat = function concat (list, length) {
  if (!Array.isArray(list)) {
    throw new TypeError('"list" argument must be an Array of Buffers')
  }

  if (list.length === 0) {
    return Buffer.alloc(0)
  }

  var i
  if (length === undefined) {
    length = 0
    for (i = 0; i < list.length; ++i) {
      length += list[i].length
    }
  }

  var buffer = Buffer.allocUnsafe(length)
  var pos = 0
  for (i = 0; i < list.length; ++i) {
    var buf = list[i]
    if (!Buffer.isBuffer(buf)) {
      throw new TypeError('"list" argument must be an Array of Buffers')
    }
    buf.copy(buffer, pos)
    pos += buf.length
  }
  return buffer
}

function byteLength (string, encoding) {
  if (Buffer.isBuffer(string)) {
    return string.length
  }
  if (isArrayBufferView(string) || isArrayBuffer(string)) {
    return string.byteLength
  }
  if (typeof string !== 'string') {
    string = '' + string
  }

  var len = string.length
  if (len === 0) return 0

  // Use a for loop to avoid recursion
  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'ascii':
      case 'latin1':
      case 'binary':
        return len
      case 'utf8':
      case 'utf-8':
      case undefined:
        return utf8ToBytes(string).length
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return len * 2
      case 'hex':
        return len >>> 1
      case 'base64':
        return base64ToBytes(string).length
      default:
        if (loweredCase) return utf8ToBytes(string).length // assume utf8
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}
Buffer.byteLength = byteLength

function slowToString (encoding, start, end) {
  var loweredCase = false

  // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
  // property of a typed array.

  // This behaves neither like String nor Uint8Array in that we set start/end
  // to their upper/lower bounds if the value passed is out of range.
  // undefined is handled specially as per ECMA-262 6th Edition,
  // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
  if (start === undefined || start < 0) {
    start = 0
  }
  // Return early if start > this.length. Done here to prevent potential uint32
  // coercion fail below.
  if (start > this.length) {
    return ''
  }

  if (end === undefined || end > this.length) {
    end = this.length
  }

  if (end <= 0) {
    return ''
  }

  // Force coersion to uint32. This will also coerce falsey/NaN values to 0.
  end >>>= 0
  start >>>= 0

  if (end <= start) {
    return ''
  }

  if (!encoding) encoding = 'utf8'

  while (true) {
    switch (encoding) {
      case 'hex':
        return hexSlice(this, start, end)

      case 'utf8':
      case 'utf-8':
        return utf8Slice(this, start, end)

      case 'ascii':
        return asciiSlice(this, start, end)

      case 'latin1':
      case 'binary':
        return latin1Slice(this, start, end)

      case 'base64':
        return base64Slice(this, start, end)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return utf16leSlice(this, start, end)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = (encoding + '').toLowerCase()
        loweredCase = true
    }
  }
}

// This property is used by `Buffer.isBuffer` (and the `is-buffer` npm package)
// to detect a Buffer instance. It's not possible to use `instanceof Buffer`
// reliably in a browserify context because there could be multiple different
// copies of the 'buffer' package in use. This method works even for Buffer
// instances that were created from another copy of the `buffer` package.
// See: https://github.com/feross/buffer/issues/154
Buffer.prototype._isBuffer = true

function swap (b, n, m) {
  var i = b[n]
  b[n] = b[m]
  b[m] = i
}

Buffer.prototype.swap16 = function swap16 () {
  var len = this.length
  if (len % 2 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 16-bits')
  }
  for (var i = 0; i < len; i += 2) {
    swap(this, i, i + 1)
  }
  return this
}

Buffer.prototype.swap32 = function swap32 () {
  var len = this.length
  if (len % 4 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 32-bits')
  }
  for (var i = 0; i < len; i += 4) {
    swap(this, i, i + 3)
    swap(this, i + 1, i + 2)
  }
  return this
}

Buffer.prototype.swap64 = function swap64 () {
  var len = this.length
  if (len % 8 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 64-bits')
  }
  for (var i = 0; i < len; i += 8) {
    swap(this, i, i + 7)
    swap(this, i + 1, i + 6)
    swap(this, i + 2, i + 5)
    swap(this, i + 3, i + 4)
  }
  return this
}

Buffer.prototype.toString = function toString () {
  var length = this.length
  if (length === 0) return ''
  if (arguments.length === 0) return utf8Slice(this, 0, length)
  return slowToString.apply(this, arguments)
}

Buffer.prototype.equals = function equals (b) {
  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
  if (this === b) return true
  return Buffer.compare(this, b) === 0
}

Buffer.prototype.inspect = function inspect () {
  var str = ''
  var max = exports.INSPECT_MAX_BYTES
  if (this.length > 0) {
    str = this.toString('hex', 0, max).match(/.{2}/g).join(' ')
    if (this.length > max) str += ' ... '
  }
  return '<Buffer ' + str + '>'
}

Buffer.prototype.compare = function compare (target, start, end, thisStart, thisEnd) {
  if (!Buffer.isBuffer(target)) {
    throw new TypeError('Argument must be a Buffer')
  }

  if (start === undefined) {
    start = 0
  }
  if (end === undefined) {
    end = target ? target.length : 0
  }
  if (thisStart === undefined) {
    thisStart = 0
  }
  if (thisEnd === undefined) {
    thisEnd = this.length
  }

  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
    throw new RangeError('out of range index')
  }

  if (thisStart >= thisEnd && start >= end) {
    return 0
  }
  if (thisStart >= thisEnd) {
    return -1
  }
  if (start >= end) {
    return 1
  }

  start >>>= 0
  end >>>= 0
  thisStart >>>= 0
  thisEnd >>>= 0

  if (this === target) return 0

  var x = thisEnd - thisStart
  var y = end - start
  var len = Math.min(x, y)

  var thisCopy = this.slice(thisStart, thisEnd)
  var targetCopy = target.slice(start, end)

  for (var i = 0; i < len; ++i) {
    if (thisCopy[i] !== targetCopy[i]) {
      x = thisCopy[i]
      y = targetCopy[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

// Finds either the first index of `val` in `buffer` at offset >= `byteOffset`,
// OR the last index of `val` in `buffer` at offset <= `byteOffset`.
//
// Arguments:
// - buffer - a Buffer to search
// - val - a string, Buffer, or number
// - byteOffset - an index into `buffer`; will be clamped to an int32
// - encoding - an optional encoding, relevant is val is a string
// - dir - true for indexOf, false for lastIndexOf
function bidirectionalIndexOf (buffer, val, byteOffset, encoding, dir) {
  // Empty buffer means no match
  if (buffer.length === 0) return -1

  // Normalize byteOffset
  if (typeof byteOffset === 'string') {
    encoding = byteOffset
    byteOffset = 0
  } else if (byteOffset > 0x7fffffff) {
    byteOffset = 0x7fffffff
  } else if (byteOffset < -0x80000000) {
    byteOffset = -0x80000000
  }
  byteOffset = +byteOffset  // Coerce to Number.
  if (numberIsNaN(byteOffset)) {
    // byteOffset: it it's undefined, null, NaN, "foo", etc, search whole buffer
    byteOffset = dir ? 0 : (buffer.length - 1)
  }

  // Normalize byteOffset: negative offsets start from the end of the buffer
  if (byteOffset < 0) byteOffset = buffer.length + byteOffset
  if (byteOffset >= buffer.length) {
    if (dir) return -1
    else byteOffset = buffer.length - 1
  } else if (byteOffset < 0) {
    if (dir) byteOffset = 0
    else return -1
  }

  // Normalize val
  if (typeof val === 'string') {
    val = Buffer.from(val, encoding)
  }

  // Finally, search either indexOf (if dir is true) or lastIndexOf
  if (Buffer.isBuffer(val)) {
    // Special case: looking for empty string/buffer always fails
    if (val.length === 0) {
      return -1
    }
    return arrayIndexOf(buffer, val, byteOffset, encoding, dir)
  } else if (typeof val === 'number') {
    val = val & 0xFF // Search for a byte value [0-255]
    if (typeof Uint8Array.prototype.indexOf === 'function') {
      if (dir) {
        return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset)
      } else {
        return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset)
      }
    }
    return arrayIndexOf(buffer, [ val ], byteOffset, encoding, dir)
  }

  throw new TypeError('val must be string, number or Buffer')
}

function arrayIndexOf (arr, val, byteOffset, encoding, dir) {
  var indexSize = 1
  var arrLength = arr.length
  var valLength = val.length

  if (encoding !== undefined) {
    encoding = String(encoding).toLowerCase()
    if (encoding === 'ucs2' || encoding === 'ucs-2' ||
        encoding === 'utf16le' || encoding === 'utf-16le') {
      if (arr.length < 2 || val.length < 2) {
        return -1
      }
      indexSize = 2
      arrLength /= 2
      valLength /= 2
      byteOffset /= 2
    }
  }

  function read (buf, i) {
    if (indexSize === 1) {
      return buf[i]
    } else {
      return buf.readUInt16BE(i * indexSize)
    }
  }

  var i
  if (dir) {
    var foundIndex = -1
    for (i = byteOffset; i < arrLength; i++) {
      if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
        if (foundIndex === -1) foundIndex = i
        if (i - foundIndex + 1 === valLength) return foundIndex * indexSize
      } else {
        if (foundIndex !== -1) i -= i - foundIndex
        foundIndex = -1
      }
    }
  } else {
    if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength
    for (i = byteOffset; i >= 0; i--) {
      var found = true
      for (var j = 0; j < valLength; j++) {
        if (read(arr, i + j) !== read(val, j)) {
          found = false
          break
        }
      }
      if (found) return i
    }
  }

  return -1
}

Buffer.prototype.includes = function includes (val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1
}

Buffer.prototype.indexOf = function indexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, true)
}

Buffer.prototype.lastIndexOf = function lastIndexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, false)
}

function hexWrite (buf, string, offset, length) {
  offset = Number(offset) || 0
  var remaining = buf.length - offset
  if (!length) {
    length = remaining
  } else {
    length = Number(length)
    if (length > remaining) {
      length = remaining
    }
  }

  // must be an even number of digits
  var strLen = string.length
  if (strLen % 2 !== 0) throw new TypeError('Invalid hex string')

  if (length > strLen / 2) {
    length = strLen / 2
  }
  for (var i = 0; i < length; ++i) {
    var parsed = parseInt(string.substr(i * 2, 2), 16)
    if (numberIsNaN(parsed)) return i
    buf[offset + i] = parsed
  }
  return i
}

function utf8Write (buf, string, offset, length) {
  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
}

function asciiWrite (buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length)
}

function latin1Write (buf, string, offset, length) {
  return asciiWrite(buf, string, offset, length)
}

function base64Write (buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length)
}

function ucs2Write (buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
}

Buffer.prototype.write = function write (string, offset, length, encoding) {
  // Buffer#write(string)
  if (offset === undefined) {
    encoding = 'utf8'
    length = this.length
    offset = 0
  // Buffer#write(string, encoding)
  } else if (length === undefined && typeof offset === 'string') {
    encoding = offset
    length = this.length
    offset = 0
  // Buffer#write(string, offset[, length][, encoding])
  } else if (isFinite(offset)) {
    offset = offset >>> 0
    if (isFinite(length)) {
      length = length >>> 0
      if (encoding === undefined) encoding = 'utf8'
    } else {
      encoding = length
      length = undefined
    }
  } else {
    throw new Error(
      'Buffer.write(string, encoding, offset[, length]) is no longer supported'
    )
  }

  var remaining = this.length - offset
  if (length === undefined || length > remaining) length = remaining

  if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
    throw new RangeError('Attempt to write outside buffer bounds')
  }

  if (!encoding) encoding = 'utf8'

  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'hex':
        return hexWrite(this, string, offset, length)

      case 'utf8':
      case 'utf-8':
        return utf8Write(this, string, offset, length)

      case 'ascii':
        return asciiWrite(this, string, offset, length)

      case 'latin1':
      case 'binary':
        return latin1Write(this, string, offset, length)

      case 'base64':
        // Warning: maxLength not taken into account in base64Write
        return base64Write(this, string, offset, length)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return ucs2Write(this, string, offset, length)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}

Buffer.prototype.toJSON = function toJSON () {
  return {
    type: 'Buffer',
    data: Array.prototype.slice.call(this._arr || this, 0)
  }
}

function base64Slice (buf, start, end) {
  if (start === 0 && end === buf.length) {
    return base64.fromByteArray(buf)
  } else {
    return base64.fromByteArray(buf.slice(start, end))
  }
}

function utf8Slice (buf, start, end) {
  end = Math.min(buf.length, end)
  var res = []

  var i = start
  while (i < end) {
    var firstByte = buf[i]
    var codePoint = null
    var bytesPerSequence = (firstByte > 0xEF) ? 4
      : (firstByte > 0xDF) ? 3
      : (firstByte > 0xBF) ? 2
      : 1

    if (i + bytesPerSequence <= end) {
      var secondByte, thirdByte, fourthByte, tempCodePoint

      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 0x80) {
            codePoint = firstByte
          }
          break
        case 2:
          secondByte = buf[i + 1]
          if ((secondByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F)
            if (tempCodePoint > 0x7F) {
              codePoint = tempCodePoint
            }
          }
          break
        case 3:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F)
            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
              codePoint = tempCodePoint
            }
          }
          break
        case 4:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          fourthByte = buf[i + 3]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F)
            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
              codePoint = tempCodePoint
            }
          }
      }
    }

    if (codePoint === null) {
      // we did not generate a valid codePoint so insert a
      // replacement char (U+FFFD) and advance only 1 byte
      codePoint = 0xFFFD
      bytesPerSequence = 1
    } else if (codePoint > 0xFFFF) {
      // encode to utf16 (surrogate pair dance)
      codePoint -= 0x10000
      res.push(codePoint >>> 10 & 0x3FF | 0xD800)
      codePoint = 0xDC00 | codePoint & 0x3FF
    }

    res.push(codePoint)
    i += bytesPerSequence
  }

  return decodeCodePointsArray(res)
}

// Based on http://stackoverflow.com/a/22747272/680742, the browser with
// the lowest limit is Chrome, with 0x10000 args.
// We go 1 magnitude less, for safety
var MAX_ARGUMENTS_LENGTH = 0x1000

function decodeCodePointsArray (codePoints) {
  var len = codePoints.length
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
  }

  // Decode in chunks to avoid "call stack size exceeded".
  var res = ''
  var i = 0
  while (i < len) {
    res += String.fromCharCode.apply(
      String,
      codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
    )
  }
  return res
}

function asciiSlice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i] & 0x7F)
  }
  return ret
}

function latin1Slice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i])
  }
  return ret
}

function hexSlice (buf, start, end) {
  var len = buf.length

  if (!start || start < 0) start = 0
  if (!end || end < 0 || end > len) end = len

  var out = ''
  for (var i = start; i < end; ++i) {
    out += toHex(buf[i])
  }
  return out
}

function utf16leSlice (buf, start, end) {
  var bytes = buf.slice(start, end)
  var res = ''
  for (var i = 0; i < bytes.length; i += 2) {
    res += String.fromCharCode(bytes[i] + (bytes[i + 1] * 256))
  }
  return res
}

Buffer.prototype.slice = function slice (start, end) {
  var len = this.length
  start = ~~start
  end = end === undefined ? len : ~~end

  if (start < 0) {
    start += len
    if (start < 0) start = 0
  } else if (start > len) {
    start = len
  }

  if (end < 0) {
    end += len
    if (end < 0) end = 0
  } else if (end > len) {
    end = len
  }

  if (end < start) end = start

  var newBuf = this.subarray(start, end)
  // Return an augmented `Uint8Array` instance
  newBuf.__proto__ = Buffer.prototype
  return newBuf
}

/*
 * Need to make sure that buffer isn't trying to write out of bounds.
 */
function checkOffset (offset, ext, length) {
  if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
  if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
}

Buffer.prototype.readUIntLE = function readUIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }

  return val
}

Buffer.prototype.readUIntBE = function readUIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    checkOffset(offset, byteLength, this.length)
  }

  var val = this[offset + --byteLength]
  var mul = 1
  while (byteLength > 0 && (mul *= 0x100)) {
    val += this[offset + --byteLength] * mul
  }

  return val
}

Buffer.prototype.readUInt8 = function readUInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  return this[offset]
}

Buffer.prototype.readUInt16LE = function readUInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return this[offset] | (this[offset + 1] << 8)
}

Buffer.prototype.readUInt16BE = function readUInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return (this[offset] << 8) | this[offset + 1]
}

Buffer.prototype.readUInt32LE = function readUInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return ((this[offset]) |
      (this[offset + 1] << 8) |
      (this[offset + 2] << 16)) +
      (this[offset + 3] * 0x1000000)
}

Buffer.prototype.readUInt32BE = function readUInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] * 0x1000000) +
    ((this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    this[offset + 3])
}

Buffer.prototype.readIntLE = function readIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readIntBE = function readIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var i = byteLength
  var mul = 1
  var val = this[offset + --i]
  while (i > 0 && (mul *= 0x100)) {
    val += this[offset + --i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readInt8 = function readInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  if (!(this[offset] & 0x80)) return (this[offset])
  return ((0xff - this[offset] + 1) * -1)
}

Buffer.prototype.readInt16LE = function readInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset] | (this[offset + 1] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt16BE = function readInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset + 1] | (this[offset] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt32LE = function readInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset]) |
    (this[offset + 1] << 8) |
    (this[offset + 2] << 16) |
    (this[offset + 3] << 24)
}

Buffer.prototype.readInt32BE = function readInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] << 24) |
    (this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    (this[offset + 3])
}

Buffer.prototype.readFloatLE = function readFloatLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, true, 23, 4)
}

Buffer.prototype.readFloatBE = function readFloatBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, false, 23, 4)
}

Buffer.prototype.readDoubleLE = function readDoubleLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, true, 52, 8)
}

Buffer.prototype.readDoubleBE = function readDoubleBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, false, 52, 8)
}

function checkInt (buf, value, offset, ext, max, min) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance')
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds')
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
}

Buffer.prototype.writeUIntLE = function writeUIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var mul = 1
  var i = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUIntBE = function writeUIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var i = byteLength - 1
  var mul = 1
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUInt8 = function writeUInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0)
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeUInt16LE = function writeUInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeUInt16BE = function writeUInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeUInt32LE = function writeUInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset + 3] = (value >>> 24)
  this[offset + 2] = (value >>> 16)
  this[offset + 1] = (value >>> 8)
  this[offset] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeUInt32BE = function writeUInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeIntLE = function writeIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = 0
  var mul = 1
  var sub = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeIntBE = function writeIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = byteLength - 1
  var mul = 1
  var sub = 0
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeInt8 = function writeInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80)
  if (value < 0) value = 0xff + value + 1
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeInt16LE = function writeInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeInt16BE = function writeInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeInt32LE = function writeInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  this[offset + 2] = (value >>> 16)
  this[offset + 3] = (value >>> 24)
  return offset + 4
}

Buffer.prototype.writeInt32BE = function writeInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (value < 0) value = 0xffffffff + value + 1
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

function checkIEEE754 (buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
  if (offset < 0) throw new RangeError('Index out of range')
}

function writeFloat (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38)
  }
  ieee754.write(buf, value, offset, littleEndian, 23, 4)
  return offset + 4
}

Buffer.prototype.writeFloatLE = function writeFloatLE (value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert)
}

Buffer.prototype.writeFloatBE = function writeFloatBE (value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert)
}

function writeDouble (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308)
  }
  ieee754.write(buf, value, offset, littleEndian, 52, 8)
  return offset + 8
}

Buffer.prototype.writeDoubleLE = function writeDoubleLE (value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert)
}

Buffer.prototype.writeDoubleBE = function writeDoubleBE (value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert)
}

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function copy (target, targetStart, start, end) {
  if (!start) start = 0
  if (!end && end !== 0) end = this.length
  if (targetStart >= target.length) targetStart = target.length
  if (!targetStart) targetStart = 0
  if (end > 0 && end < start) end = start

  // Copy 0 bytes; we're done
  if (end === start) return 0
  if (target.length === 0 || this.length === 0) return 0

  // Fatal error conditions
  if (targetStart < 0) {
    throw new RangeError('targetStart out of bounds')
  }
  if (start < 0 || start >= this.length) throw new RangeError('sourceStart out of bounds')
  if (end < 0) throw new RangeError('sourceEnd out of bounds')

  // Are we oob?
  if (end > this.length) end = this.length
  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start
  }

  var len = end - start
  var i

  if (this === target && start < targetStart && targetStart < end) {
    // descending copy from end
    for (i = len - 1; i >= 0; --i) {
      target[i + targetStart] = this[i + start]
    }
  } else if (len < 1000) {
    // ascending copy from start
    for (i = 0; i < len; ++i) {
      target[i + targetStart] = this[i + start]
    }
  } else {
    Uint8Array.prototype.set.call(
      target,
      this.subarray(start, start + len),
      targetStart
    )
  }

  return len
}

// Usage:
//    buffer.fill(number[, offset[, end]])
//    buffer.fill(buffer[, offset[, end]])
//    buffer.fill(string[, offset[, end]][, encoding])
Buffer.prototype.fill = function fill (val, start, end, encoding) {
  // Handle string cases:
  if (typeof val === 'string') {
    if (typeof start === 'string') {
      encoding = start
      start = 0
      end = this.length
    } else if (typeof end === 'string') {
      encoding = end
      end = this.length
    }
    if (val.length === 1) {
      var code = val.charCodeAt(0)
      if (code < 256) {
        val = code
      }
    }
    if (encoding !== undefined && typeof encoding !== 'string') {
      throw new TypeError('encoding must be a string')
    }
    if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
      throw new TypeError('Unknown encoding: ' + encoding)
    }
  } else if (typeof val === 'number') {
    val = val & 255
  }

  // Invalid ranges are not set to a default, so can range check early.
  if (start < 0 || this.length < start || this.length < end) {
    throw new RangeError('Out of range index')
  }

  if (end <= start) {
    return this
  }

  start = start >>> 0
  end = end === undefined ? this.length : end >>> 0

  if (!val) val = 0

  var i
  if (typeof val === 'number') {
    for (i = start; i < end; ++i) {
      this[i] = val
    }
  } else {
    var bytes = Buffer.isBuffer(val)
      ? val
      : new Buffer(val, encoding)
    var len = bytes.length
    for (i = 0; i < end - start; ++i) {
      this[i + start] = bytes[i % len]
    }
  }

  return this
}

// HELPER FUNCTIONS
// ================

var INVALID_BASE64_RE = /[^+/0-9A-Za-z-_]/g

function base64clean (str) {
  // Node strips out invalid characters like \n and \t from the string, base64-js does not
  str = str.trim().replace(INVALID_BASE64_RE, '')
  // Node converts strings with length < 2 to ''
  if (str.length < 2) return ''
  // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
  while (str.length % 4 !== 0) {
    str = str + '='
  }
  return str
}

function toHex (n) {
  if (n < 16) return '0' + n.toString(16)
  return n.toString(16)
}

function utf8ToBytes (string, units) {
  units = units || Infinity
  var codePoint
  var length = string.length
  var leadSurrogate = null
  var bytes = []

  for (var i = 0; i < length; ++i) {
    codePoint = string.charCodeAt(i)

    // is surrogate component
    if (codePoint > 0xD7FF && codePoint < 0xE000) {
      // last char was a lead
      if (!leadSurrogate) {
        // no lead yet
        if (codePoint > 0xDBFF) {
          // unexpected trail
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        } else if (i + 1 === length) {
          // unpaired lead
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        }

        // valid lead
        leadSurrogate = codePoint

        continue
      }

      // 2 leads in a row
      if (codePoint < 0xDC00) {
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
        leadSurrogate = codePoint
        continue
      }

      // valid surrogate pair
      codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000
    } else if (leadSurrogate) {
      // valid bmp char, but last char was a lead
      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
    }

    leadSurrogate = null

    // encode utf8
    if (codePoint < 0x80) {
      if ((units -= 1) < 0) break
      bytes.push(codePoint)
    } else if (codePoint < 0x800) {
      if ((units -= 2) < 0) break
      bytes.push(
        codePoint >> 0x6 | 0xC0,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x10000) {
      if ((units -= 3) < 0) break
      bytes.push(
        codePoint >> 0xC | 0xE0,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x110000) {
      if ((units -= 4) < 0) break
      bytes.push(
        codePoint >> 0x12 | 0xF0,
        codePoint >> 0xC & 0x3F | 0x80,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else {
      throw new Error('Invalid code point')
    }
  }

  return bytes
}

function asciiToBytes (str) {
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push(str.charCodeAt(i) & 0xFF)
  }
  return byteArray
}

function utf16leToBytes (str, units) {
  var c, hi, lo
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    if ((units -= 2) < 0) break

    c = str.charCodeAt(i)
    hi = c >> 8
    lo = c % 256
    byteArray.push(lo)
    byteArray.push(hi)
  }

  return byteArray
}

function base64ToBytes (str) {
  return base64.toByteArray(base64clean(str))
}

function blitBuffer (src, dst, offset, length) {
  for (var i = 0; i < length; ++i) {
    if ((i + offset >= dst.length) || (i >= src.length)) break
    dst[i + offset] = src[i]
  }
  return i
}

// ArrayBuffers from another context (i.e. an iframe) do not pass the `instanceof` check
// but they should be treated as valid. See: https://github.com/feross/buffer/issues/166
function isArrayBuffer (obj) {
  return obj instanceof ArrayBuffer ||
    (obj != null && obj.constructor != null && obj.constructor.name === 'ArrayBuffer' &&
      typeof obj.byteLength === 'number')
}

// Node 0.10 supports `ArrayBuffer` but lacks `ArrayBuffer.isView`
function isArrayBufferView (obj) {
  return (typeof ArrayBuffer.isView === 'function') && ArrayBuffer.isView(obj)
}

function numberIsNaN (obj) {
  return obj !== obj // eslint-disable-line no-self-compare
}

},{"base64-js":9,"ieee754":19}],13:[function(require,module,exports){
// Utf8 bytes array from/to string.
// Copyright (c) Chao Wang <hit9@icloud.com>

exports.fromString = function(s) {
  var idx = 0;
  var len = s.length;
  var bytes = [];

  while (idx < len) {
    var c = s.charCodeAt(idx++);
    var buf = [];

    if (c <= 0x7f) {
      // 0XXX XXXX 1 byte
      buf[0] = c;
      buf.length = 1;
    } else if (c <= 0x7ff) {
      // 110X XXXX 2 bytes
      buf[0] = (0xc0 | (c >> 6));
      buf[1] = (0x80 | (c & 0x3f));
      buf.length = 2;
    } else if (c <= 0xffff) {
      // 1110 XXXX 3 bytes
      buf[0] = (0xe0 | (c >> 12));
      buf[1] = (0x80 | ((c >> 6) & 0x3f));
      buf[2] = (0x80 | (c & 0x3f));
      buf.length = 3;
    }
    [].push.apply(bytes, buf);
  }
  return bytes;
};

exports.toString = function(bytes) {
  var buf = [];
  var idx = 0;
  var len = bytes.length;

  while (idx < len) {
    var c = bytes[idx++];

    if ((c & 0x80) == 0) {
      // 0XXX XXXX 1 byte (0x00 ~ 0x7f)
      buf.push(c);
    } else if ((c & 0xe0) == 0xc0) {
      // 110X XXXX 2 bytes (0xc2 ~ 0xdf)
      var d = bytes[idx++];
      buf.push(((c & 0x1f) << 6) | (d & 0x3f));
    } else if ((c & 0xf0) == 0xe0) {
      // 1110 XXXX 3 bytes (0xe0 ~ 0xe1, 0xee ~ 0xef)
      var d = bytes[idx++];
      var e = bytes[idx++];
      buf.push(((c & 0x0f) << 12) | ((d & 0x3f) << 6) | (e & 0x3f));
    } else if ((c & 0xf8) == 0xf0) {
      // 1111 0XXX 4 bytes (0xf0 ~ 0xf4)
      var d = bytes[idx++];
      var e = bytes[idx++];
      var f = bytes[idx++];
      buf.push(((c & 0x0f) << 18) | ((d & 0x3f) << 12) |
               ((e & 0x3f) << 6) | (f & 0x3f));
    }
  }

  return String.fromCharCode.apply(null, buf);
};

},{}],14:[function(require,module,exports){
(function (Buffer){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

// NOTE: These type checking functions intentionally don't use `instanceof`
// because it is fragile and can be easily faked with `Object.create()`.

function isArray(arg) {
  if (Array.isArray) {
    return Array.isArray(arg);
  }
  return objectToString(arg) === '[object Array]';
}
exports.isArray = isArray;

function isBoolean(arg) {
  return typeof arg === 'boolean';
}
exports.isBoolean = isBoolean;

function isNull(arg) {
  return arg === null;
}
exports.isNull = isNull;

function isNullOrUndefined(arg) {
  return arg == null;
}
exports.isNullOrUndefined = isNullOrUndefined;

function isNumber(arg) {
  return typeof arg === 'number';
}
exports.isNumber = isNumber;

function isString(arg) {
  return typeof arg === 'string';
}
exports.isString = isString;

function isSymbol(arg) {
  return typeof arg === 'symbol';
}
exports.isSymbol = isSymbol;

function isUndefined(arg) {
  return arg === void 0;
}
exports.isUndefined = isUndefined;

function isRegExp(re) {
  return objectToString(re) === '[object RegExp]';
}
exports.isRegExp = isRegExp;

function isObject(arg) {
  return typeof arg === 'object' && arg !== null;
}
exports.isObject = isObject;

function isDate(d) {
  return objectToString(d) === '[object Date]';
}
exports.isDate = isDate;

function isError(e) {
  return (objectToString(e) === '[object Error]' || e instanceof Error);
}
exports.isError = isError;

function isFunction(arg) {
  return typeof arg === 'function';
}
exports.isFunction = isFunction;

function isPrimitive(arg) {
  return arg === null ||
         typeof arg === 'boolean' ||
         typeof arg === 'number' ||
         typeof arg === 'string' ||
         typeof arg === 'symbol' ||  // ES6 symbol
         typeof arg === 'undefined';
}
exports.isPrimitive = isPrimitive;

exports.isBuffer = Buffer.isBuffer;

function objectToString(o) {
  return Object.prototype.toString.call(o);
}

}).call(this,{"isBuffer":require("../../is-buffer/index.js")})
},{"../../is-buffer/index.js":21}],15:[function(require,module,exports){
var window = require('global/window');
var nodeCrypto = require('crypto');

function getRandomValues(buf) {
  if (window.crypto && window.crypto.getRandomValues) {
    return window.crypto.getRandomValues(buf);
  }
  if (typeof window.msCrypto === 'object' && typeof window.msCrypto.getRandomValues === 'function') {
    return window.msCrypto.getRandomValues(buf);
  }
  if (nodeCrypto.randomBytes) {
    if (!(buf instanceof Uint8Array)) {
      throw new TypeError('expected Uint8Array');
    }
    if (buf.length > 65536) {
      var e = new Error();
      e.code = 22;
      e.message = 'Failed to execute \'getRandomValues\' on \'Crypto\': The ' +
        'ArrayBufferView\'s byte length (' + buf.length + ') exceeds the ' +
        'number of bytes of entropy available via this API (65536).';
      e.name = 'QuotaExceededError';
      throw e;
    }
    var bytes = nodeCrypto.randomBytes(buf.length);
    buf.set(bytes);
    return buf;
  }
  else {
    throw new Error('No secure random number generator available.');
  }
}

module.exports = getRandomValues;

},{"crypto":11,"global/window":16}],16:[function(require,module,exports){
(function (global){
var win;

if (typeof window !== "undefined") {
    win = window;
} else if (typeof global !== "undefined") {
    win = global;
} else if (typeof self !== "undefined"){
    win = self;
} else {
    win = {};
}

module.exports = win;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}],17:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

function EventEmitter() {
  this._events = this._events || {};
  this._maxListeners = this._maxListeners || undefined;
}
module.exports = EventEmitter;

// Backwards-compat with node 0.10.x
EventEmitter.EventEmitter = EventEmitter;

EventEmitter.prototype._events = undefined;
EventEmitter.prototype._maxListeners = undefined;

// By default EventEmitters will print a warning if more than 10 listeners are
// added to it. This is a useful default which helps finding memory leaks.
EventEmitter.defaultMaxListeners = 10;

// Obviously not all Emitters should be limited to 10. This function allows
// that to be increased. Set to zero for unlimited.
EventEmitter.prototype.setMaxListeners = function(n) {
  if (!isNumber(n) || n < 0 || isNaN(n))
    throw TypeError('n must be a positive number');
  this._maxListeners = n;
  return this;
};

EventEmitter.prototype.emit = function(type) {
  var er, handler, len, args, i, listeners;

  if (!this._events)
    this._events = {};

  // If there is no 'error' event listener then throw.
  if (type === 'error') {
    if (!this._events.error ||
        (isObject(this._events.error) && !this._events.error.length)) {
      er = arguments[1];
      if (er instanceof Error) {
        throw er; // Unhandled 'error' event
      } else {
        // At least give some kind of context to the user
        var err = new Error('Uncaught, unspecified "error" event. (' + er + ')');
        err.context = er;
        throw err;
      }
    }
  }

  handler = this._events[type];

  if (isUndefined(handler))
    return false;

  if (isFunction(handler)) {
    switch (arguments.length) {
      // fast cases
      case 1:
        handler.call(this);
        break;
      case 2:
        handler.call(this, arguments[1]);
        break;
      case 3:
        handler.call(this, arguments[1], arguments[2]);
        break;
      // slower
      default:
        args = Array.prototype.slice.call(arguments, 1);
        handler.apply(this, args);
    }
  } else if (isObject(handler)) {
    args = Array.prototype.slice.call(arguments, 1);
    listeners = handler.slice();
    len = listeners.length;
    for (i = 0; i < len; i++)
      listeners[i].apply(this, args);
  }

  return true;
};

EventEmitter.prototype.addListener = function(type, listener) {
  var m;

  if (!isFunction(listener))
    throw TypeError('listener must be a function');

  if (!this._events)
    this._events = {};

  // To avoid recursion in the case that type === "newListener"! Before
  // adding it to the listeners, first emit "newListener".
  if (this._events.newListener)
    this.emit('newListener', type,
              isFunction(listener.listener) ?
              listener.listener : listener);

  if (!this._events[type])
    // Optimize the case of one listener. Don't need the extra array object.
    this._events[type] = listener;
  else if (isObject(this._events[type]))
    // If we've already got an array, just append.
    this._events[type].push(listener);
  else
    // Adding the second element, need to change to array.
    this._events[type] = [this._events[type], listener];

  // Check for listener leak
  if (isObject(this._events[type]) && !this._events[type].warned) {
    if (!isUndefined(this._maxListeners)) {
      m = this._maxListeners;
    } else {
      m = EventEmitter.defaultMaxListeners;
    }

    if (m && m > 0 && this._events[type].length > m) {
      this._events[type].warned = true;
      console.error('(node) warning: possible EventEmitter memory ' +
                    'leak detected. %d listeners added. ' +
                    'Use emitter.setMaxListeners() to increase limit.',
                    this._events[type].length);
      if (typeof console.trace === 'function') {
        // not supported in IE 10
        console.trace();
      }
    }
  }

  return this;
};

EventEmitter.prototype.on = EventEmitter.prototype.addListener;

EventEmitter.prototype.once = function(type, listener) {
  if (!isFunction(listener))
    throw TypeError('listener must be a function');

  var fired = false;

  function g() {
    this.removeListener(type, g);

    if (!fired) {
      fired = true;
      listener.apply(this, arguments);
    }
  }

  g.listener = listener;
  this.on(type, g);

  return this;
};

// emits a 'removeListener' event iff the listener was removed
EventEmitter.prototype.removeListener = function(type, listener) {
  var list, position, length, i;

  if (!isFunction(listener))
    throw TypeError('listener must be a function');

  if (!this._events || !this._events[type])
    return this;

  list = this._events[type];
  length = list.length;
  position = -1;

  if (list === listener ||
      (isFunction(list.listener) && list.listener === listener)) {
    delete this._events[type];
    if (this._events.removeListener)
      this.emit('removeListener', type, listener);

  } else if (isObject(list)) {
    for (i = length; i-- > 0;) {
      if (list[i] === listener ||
          (list[i].listener && list[i].listener === listener)) {
        position = i;
        break;
      }
    }

    if (position < 0)
      return this;

    if (list.length === 1) {
      list.length = 0;
      delete this._events[type];
    } else {
      list.splice(position, 1);
    }

    if (this._events.removeListener)
      this.emit('removeListener', type, listener);
  }

  return this;
};

EventEmitter.prototype.removeAllListeners = function(type) {
  var key, listeners;

  if (!this._events)
    return this;

  // not listening for removeListener, no need to emit
  if (!this._events.removeListener) {
    if (arguments.length === 0)
      this._events = {};
    else if (this._events[type])
      delete this._events[type];
    return this;
  }

  // emit removeListener for all listeners on all events
  if (arguments.length === 0) {
    for (key in this._events) {
      if (key === 'removeListener') continue;
      this.removeAllListeners(key);
    }
    this.removeAllListeners('removeListener');
    this._events = {};
    return this;
  }

  listeners = this._events[type];

  if (isFunction(listeners)) {
    this.removeListener(type, listeners);
  } else if (listeners) {
    // LIFO order
    while (listeners.length)
      this.removeListener(type, listeners[listeners.length - 1]);
  }
  delete this._events[type];

  return this;
};

EventEmitter.prototype.listeners = function(type) {
  var ret;
  if (!this._events || !this._events[type])
    ret = [];
  else if (isFunction(this._events[type]))
    ret = [this._events[type]];
  else
    ret = this._events[type].slice();
  return ret;
};

EventEmitter.prototype.listenerCount = function(type) {
  if (this._events) {
    var evlistener = this._events[type];

    if (isFunction(evlistener))
      return 1;
    else if (evlistener)
      return evlistener.length;
  }
  return 0;
};

EventEmitter.listenerCount = function(emitter, type) {
  return emitter.listenerCount(type);
};

function isFunction(arg) {
  return typeof arg === 'function';
}

function isNumber(arg) {
  return typeof arg === 'number';
}

function isObject(arg) {
  return typeof arg === 'object' && arg !== null;
}

function isUndefined(arg) {
  return arg === void 0;
}

},{}],18:[function(require,module,exports){
// shim for using process in browser
var process = module.exports = {};

// cached from whatever global is present so that test runners that stub it
// don't break things.  But we need to wrap it in a try catch in case it is
// wrapped in strict mode code which doesn't define any globals.  It's inside a
// function because try/catches deoptimize in certain engines.

var cachedSetTimeout;
var cachedClearTimeout;

function defaultSetTimout() {
    throw new Error('setTimeout has not been defined');
}
function defaultClearTimeout () {
    throw new Error('clearTimeout has not been defined');
}
(function () {
    try {
        if (typeof setTimeout === 'function') {
            cachedSetTimeout = setTimeout;
        } else {
            cachedSetTimeout = defaultSetTimout;
        }
    } catch (e) {
        cachedSetTimeout = defaultSetTimout;
    }
    try {
        if (typeof clearTimeout === 'function') {
            cachedClearTimeout = clearTimeout;
        } else {
            cachedClearTimeout = defaultClearTimeout;
        }
    } catch (e) {
        cachedClearTimeout = defaultClearTimeout;
    }
} ())
function runTimeout(fun) {
    if (cachedSetTimeout === setTimeout) {
        //normal enviroments in sane situations
        return setTimeout(fun, 0);
    }
    // if setTimeout wasn't available but was latter defined
    if ((cachedSetTimeout === defaultSetTimout || !cachedSetTimeout) && setTimeout) {
        cachedSetTimeout = setTimeout;
        return setTimeout(fun, 0);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedSetTimeout(fun, 0);
    } catch(e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't trust the global object when called normally
            return cachedSetTimeout.call(null, fun, 0);
        } catch(e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error
            return cachedSetTimeout.call(this, fun, 0);
        }
    }


}
function runClearTimeout(marker) {
    if (cachedClearTimeout === clearTimeout) {
        //normal enviroments in sane situations
        return clearTimeout(marker);
    }
    // if clearTimeout wasn't available but was latter defined
    if ((cachedClearTimeout === defaultClearTimeout || !cachedClearTimeout) && clearTimeout) {
        cachedClearTimeout = clearTimeout;
        return clearTimeout(marker);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedClearTimeout(marker);
    } catch (e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't  trust the global object when called normally
            return cachedClearTimeout.call(null, marker);
        } catch (e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error.
            // Some versions of I.E. have different rules for clearTimeout vs setTimeout
            return cachedClearTimeout.call(this, marker);
        }
    }



}
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;

function cleanUpNextTick() {
    if (!draining || !currentQueue) {
        return;
    }
    draining = false;
    if (currentQueue.length) {
        queue = currentQueue.concat(queue);
    } else {
        queueIndex = -1;
    }
    if (queue.length) {
        drainQueue();
    }
}

function drainQueue() {
    if (draining) {
        return;
    }
    var timeout = runTimeout(cleanUpNextTick);
    draining = true;

    var len = queue.length;
    while(len) {
        currentQueue = queue;
        queue = [];
        while (++queueIndex < len) {
            if (currentQueue) {
                currentQueue[queueIndex].run();
            }
        }
        queueIndex = -1;
        len = queue.length;
    }
    currentQueue = null;
    draining = false;
    runClearTimeout(timeout);
}

process.nextTick = function (fun) {
    var args = new Array(arguments.length - 1);
    if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
            args[i - 1] = arguments[i];
        }
    }
    queue.push(new Item(fun, args));
    if (queue.length === 1 && !draining) {
        runTimeout(drainQueue);
    }
};

// v8 likes predictible objects
function Item(fun, array) {
    this.fun = fun;
    this.array = array;
}
Item.prototype.run = function () {
    this.fun.apply(null, this.array);
};
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

function noop() {}

process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;
process.prependListener = noop;
process.prependOnceListener = noop;

process.listeners = function (name) { return [] }

process.binding = function (name) {
    throw new Error('process.binding is not supported');
};

process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};
process.umask = function() { return 0; };

},{}],19:[function(require,module,exports){
exports.read = function (buffer, offset, isLE, mLen, nBytes) {
  var e, m
  var eLen = nBytes * 8 - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var nBits = -7
  var i = isLE ? (nBytes - 1) : 0
  var d = isLE ? -1 : 1
  var s = buffer[offset + i]

  i += d

  e = s & ((1 << (-nBits)) - 1)
  s >>= (-nBits)
  nBits += eLen
  for (; nBits > 0; e = e * 256 + buffer[offset + i], i += d, nBits -= 8) {}

  m = e & ((1 << (-nBits)) - 1)
  e >>= (-nBits)
  nBits += mLen
  for (; nBits > 0; m = m * 256 + buffer[offset + i], i += d, nBits -= 8) {}

  if (e === 0) {
    e = 1 - eBias
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity)
  } else {
    m = m + Math.pow(2, mLen)
    e = e - eBias
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
}

exports.write = function (buffer, value, offset, isLE, mLen, nBytes) {
  var e, m, c
  var eLen = nBytes * 8 - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0)
  var i = isLE ? 0 : (nBytes - 1)
  var d = isLE ? 1 : -1
  var s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0

  value = Math.abs(value)

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0
    e = eMax
  } else {
    e = Math.floor(Math.log(value) / Math.LN2)
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--
      c *= 2
    }
    if (e + eBias >= 1) {
      value += rt / c
    } else {
      value += rt * Math.pow(2, 1 - eBias)
    }
    if (value * c >= 2) {
      e++
      c /= 2
    }

    if (e + eBias >= eMax) {
      m = 0
      e = eMax
    } else if (e + eBias >= 1) {
      m = (value * c - 1) * Math.pow(2, mLen)
      e = e + eBias
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen)
      e = 0
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8) {}

  e = (e << mLen) | m
  eLen += mLen
  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8) {}

  buffer[offset + i - d] |= s * 128
}

},{}],20:[function(require,module,exports){
if (typeof Object.create === 'function') {
  // implementation from standard node.js 'util' module
  module.exports = function inherits(ctor, superCtor) {
    ctor.super_ = superCtor
    ctor.prototype = Object.create(superCtor.prototype, {
      constructor: {
        value: ctor,
        enumerable: false,
        writable: true,
        configurable: true
      }
    });
  };
} else {
  // old school shim for old browsers
  module.exports = function inherits(ctor, superCtor) {
    ctor.super_ = superCtor
    var TempCtor = function () {}
    TempCtor.prototype = superCtor.prototype
    ctor.prototype = new TempCtor()
    ctor.prototype.constructor = ctor
  }
}

},{}],21:[function(require,module,exports){
/*!
 * Determine if an object is a Buffer
 *
 * @author   Feross Aboukhadijeh <https://feross.org>
 * @license  MIT
 */

// The _isBuffer check is for Safari 5-7 support, because it's missing
// Object.prototype.constructor. Remove this eventually
module.exports = function (obj) {
  return obj != null && (isBuffer(obj) || isSlowBuffer(obj) || !!obj._isBuffer)
}

function isBuffer (obj) {
  return !!obj.constructor && typeof obj.constructor.isBuffer === 'function' && obj.constructor.isBuffer(obj)
}

// For Node v0.10 support. Remove this eventually.
function isSlowBuffer (obj) {
  return typeof obj.readFloatLE === 'function' && typeof obj.slice === 'function' && isBuffer(obj.slice(0, 0))
}

},{}],22:[function(require,module,exports){
var toString = {}.toString;

module.exports = Array.isArray || function (arr) {
  return toString.call(arr) == '[object Array]';
};

},{}],23:[function(require,module,exports){
module.exports = require("./src/ctx");

},{"./src/ctx":24}],24:[function(require,module,exports){
/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/


var CTX = function(input_parameter) {
    "use strict";

    var ctx = this,
        CTXLIST,
        prepareModule;

    CTXLIST = {
        "ED25519": {
            "BITS": "256",
            "FIELD": "25519",
            "CURVE": "ED25519",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 255,
            "@M8": 5,
            "@MT": 1,
            "@CT": 1,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0
        },

        "C25519": {
            "BITS": "256",
            "FIELD": "25519",
            "CURVE": "C25519",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 255,
            "@M8": 5,
            "@MT": 1,
            "@CT": 2,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0
        },

        "NIST256": {
            "BITS": "256",
            "FIELD": "NIST256",
            "CURVE": "NIST256",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 256,
            "@M8": 7,
            "@MT": 0,
            "@CT": 0,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0
        },

        "NIST384": {
            "BITS": "384",
            "FIELD": "NIST384",
            "CURVE": "NIST384",
            "@NB": 48,
            "@BASE": 23,
            "@NBT": 384,
            "@M8": 7,
            "@MT": 0,
            "@CT": 0,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0
        },

        "BRAINPOOL": {
            "BITS": "256",
            "FIELD": "BRAINPOOL",
            "CURVE": "BRAINPOOL",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 256,
            "@M8": 7,
            "@MT": 0,
            "@CT": 0,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0
        },

        "ANSSI": {
            "BITS": "256",
            "FIELD": "ANSSI",
            "CURVE": "ANSSI",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 256,
            "@M8": 7,
            "@MT": 0,
            "@CT": 0,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0
        },

        "HIFIVE": {
            "BITS": "336",
            "FIELD": "HIFIVE",
            "CURVE": "HIFIVE",
            "@NB": 42,
            "@BASE": 23,
            "@NBT": 336,
            "@M8": 5,
            "@MT": 1,
            "@CT": 1,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0
        },

        "GOLDILOCKS": {
            "BITS": "448",
            "FIELD": "GOLDILOCKS",
            "CURVE": "GOLDILOCKS",
            "@NB": 56,
            "@BASE": 23,
            "@NBT": 448,
            "@M8": 7,
            "@MT": 2,
            "@CT": 1,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0
        },

        "C41417": {
            "BITS": "416",
            "FIELD": "C41417",
            "CURVE": "C41417",
            "@NB": 52,
            "@BASE": 22,
            "@NBT": 414,
            "@M8": 7,
            "@MT": 1,
            "@CT": 1,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0
        },

        "NIST521": {
            "BITS": "528",
            "FIELD": "NIST521",
            "CURVE": "NIST521",
            "@NB": 66,
            "@BASE": 23,
            "@NBT": 521,
            "@M8": 7,
            "@MT": 1,
            "@CT": 0,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0
        },

        "NUMS256W": {
            "BITS": "256",
            "FIELD": "256PM",
            "CURVE": "NUMS256W",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 256,
            "@M8": 3,
            "@MT": 1,
            "@CT": 0,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0
        },

        "NUMS256E": {
            "BITS": "256",
            "FIELD": "256PM",
            "CURVE": "NUMS256E",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 256,
            "@M8": 3,
            "@MT": 1,
            "@CT": 1,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0
        },

        "NUMS384W": {
            "BITS": "384",
            "FIELD": "384PM",
            "CURVE": "NUMS384W",
            "@NB": 48,
            "@BASE": 23,
            "@NBT": 384,
            "@M8": 3,
            "@MT": 1,
            "@CT": 0,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0
        },

        "NUMS384E": {
            "BITS": "384",
            "FIELD": "384PM",
            "CURVE": "NUMS384E",
            "@NB": 48,
            "@BASE": 23,
            "@NBT": 384,
            "@M8": 3,
            "@MT": 1,
            "@CT": 1,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0
        },

        "NUMS512W": {
            "BITS": "512",
            "FIELD": "512PM",
            "CURVE": "NUMS512W",
            "@NB": 64,
            "@BASE": 23,
            "@NBT": 512,
            "@M8": 7,
            "@MT": 1,
            "@CT": 0,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0
        },

        "NUMS512E": {
            "BITS": "512",
            "FIELD": "512PM",
            "CURVE": "NUMS512E",
            "@NB": 64,
            "@BASE": 23,
            "@NBT": 512,
            "@M8": 7,
            "@MT": 1,
            "@CT": 1,
            "@PF": 0,
            "@ST": 0,
            "@SX": 0
        },

        "FP256BN": {
            "BITS": "256",
            "FIELD": "FP256BN",
            "CURVE": "FP256BN",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 256,
            "@M8": 3,
            "@MT": 0,
            "@CT": 0,
            "@PF": 1,
            "@ST": 1,
            "@SX": 1
        },

        "FP512BN": {
            "BITS": "512",
            "FIELD": "FP512BN",
            "CURVE": "FP512BN",
            "@NB": 64,
            "@BASE": 23,
            "@NBT": 512,
            "@M8": 3,
            "@MT": 0,
            "@CT": 0,
            "@PF": 1,
            "@ST": 1,
            "@SX": 0
        },

        "BN254": {
            "BITS": "256",
            "FIELD": "BN254",
            "CURVE": "BN254",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 254,
            "@M8": 3,
            "@MT": 0,
            "@CT": 0,
            "@PF": 1,
            "@ST": 0,
            "@SX": 1
        },

        "BN254CX": {
            "BITS": "256",
            "FIELD": "BN254CX",
            "CURVE": "BN254CX",
            "@NB": 32,
            "@BASE": 24,
            "@NBT": 254,
            "@M8": 3,
            "@MT": 0,
            "@CT": 0,
            "@PF": 1,
            "@ST": 0,
            "@SX": 1
        },

        "BLS383": {
            "BITS": "384",
            "FIELD": "BLS383",
            "CURVE": "BLS383",
            "@NB": 48,
            "@BASE": 23,
            "@NBT": 383,
            "@M8": 3,
            "@MT": 0,
            "@CT": 0,
            "@PF": 2,
            "@ST": 0,
            "@SX": 0
        },

        "BLS461": {
            "BITS": "464",
            "FIELD": "BLS461",
            "CURVE": "BLS461",
            "@NB": 58,
            "@BASE": 23,
            "@NBT": 461,
            "@M8": 3,
            "@MT": 0,
            "@CT": 0,
            "@PF": 2,
            "@ST": 1,
            "@SX": 1
        },

        "RSA2048": {
            "BITS": "1024",
            "TFF": "2048",
            "@NB": 128,
            "@BASE": 22,
            "@ML": 2,
        },

        "RSA3072": {
            "BITS": "384",
            "TFF": "3072",
            "@NB": 48,
            "@BASE": 23,
            "@ML": 8,
        },

        "RSA4096": {
            "BITS": "512",
            "TFF": "4096",
            "@NB": 64,
            "@BASE": 23,
            "@ML": 8,
        },
    };

    prepareModule = function (moduleName, fileName, propertyName) {
        if (!propertyName) {
            propertyName = moduleName;
        }

        if (typeof require !== "undefined") {
            if (!fileName) {
                fileName = moduleName.toLowerCase();
            }

            ctx[propertyName] = require("./" + fileName)[moduleName](ctx);
        } else {
            ctx[propertyName] = window[moduleName](ctx);
        }
    };

    prepareModule("AES");
    prepareModule("GCM");
    prepareModule("UInt64");
    prepareModule("HASH256");
    prepareModule("HASH384");
    prepareModule("HASH512");
    prepareModule("SHA3");
    prepareModule("RAND");
    prepareModule("NewHope");
    prepareModule("NHS");

    if (typeof input_parameter === "undefined") {
        return;
    }

    ctx.config = CTXLIST[input_parameter];

    prepareModule("BIG");
    prepareModule("DBIG", "big");

    // Set RSA parameters
    if (typeof ctx.config["TFF"] !== "undefined") {
        prepareModule("FF");
        prepareModule("RSA");
        prepareModule("rsa_public_key", "rsa");
        prepareModule("rsa_private_key", "rsa");
        return;
    }

    // Set Elliptic Curve parameters
    if (typeof ctx.config["CURVE"] !== "undefined") {
        prepareModule("ROM_CURVE_" + ctx.config["CURVE"], "rom_curve", "ROM_CURVE");
        prepareModule("ROM_FIELD_" + ctx.config["FIELD"], "rom_field", "ROM_FIELD");

        prepareModule("FP");
        prepareModule("ECP");
        prepareModule("ECDH");

        if (ctx.config["@PF"] != 0) {
            prepareModule("FP2");
            prepareModule("FP4");
            prepareModule("FP12");
            prepareModule("ECP2");
            prepareModule("PAIR");
            prepareModule("MPIN");
        }

        return;
    }

};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = CTX;
}

},{}],25:[function(require,module,exports){
'use strict'

var Buffer = require('safe-buffer').Buffer
var assert = require('assert')
var bl = require('bl')
var streams = require('./lib/streams')
var buildDecode = require('./lib/decoder')
var buildEncode = require('./lib/encoder')

function msgpack (options) {
  var encodingTypes = []
  var decodingTypes = []

  options = options || {
    forceFloat64: false,
    compatibilityMode: false,
    disableTimestampEncoding: false // if true, skips encoding Dates using the msgpack timestamp ext format (-1)
  }

  function registerEncoder (check, encode) {
    assert(check, 'must have an encode function')
    assert(encode, 'must have an encode function')

    encodingTypes.push({
      check: check, encode: encode
    })

    return this
  }

  function registerDecoder (type, decode) {
    assert(type >= 0, 'must have a non-negative type')
    assert(decode, 'must have a decode function')

    decodingTypes.push({
      type: type, decode: decode
    })

    return this
  }

  function register (type, constructor, encode, decode) {
    assert(constructor, 'must have a constructor')
    assert(encode, 'must have an encode function')
    assert(type >= 0, 'must have a non-negative type')
    assert(decode, 'must have a decode function')

    function check (obj) {
      return (obj instanceof constructor)
    }

    function reEncode (obj) {
      var buf = bl()
      var header = Buffer.allocUnsafe(1)

      header.writeInt8(type, 0)

      buf.append(header)
      buf.append(encode(obj))

      return buf
    }

    this.registerEncoder(check, reEncode)
    this.registerDecoder(type, decode)

    return this
  }

  return {
    encode: buildEncode(encodingTypes, options.forceFloat64, options.compatibilityMode, options.disableTimestampEncoding),
    decode: buildDecode(decodingTypes),
    register: register,
    registerEncoder: registerEncoder,
    registerDecoder: registerDecoder,
    encoder: streams.encoder,
    decoder: streams.decoder,
    // needed for levelup support
    buffer: true,
    type: 'msgpack5',
    IncompleteBufferError: buildDecode.IncompleteBufferError
  }
}

module.exports = msgpack

},{"./lib/decoder":26,"./lib/encoder":27,"./lib/streams":28,"assert":8,"bl":10,"safe-buffer":40}],26:[function(require,module,exports){
var bl = require('bl')
var util = require('util')

function IncompleteBufferError (message) {
  Error.call(this) // super constructor
  if (Error.captureStackTrace) {
    Error.captureStackTrace(this, this.constructor) // super helper method to include stack trace in error object
  }
  this.name = this.constructor.name
  this.message = message || 'unable to decode'
}

util.inherits(IncompleteBufferError, Error)

module.exports = function buildDecode (decodingTypes) {
  return decode

  function getSize (first) {
    switch (first) {
      case 0xc4:
        return 2
      case 0xc5:
        return 3
      case 0xc6:
        return 5
      case 0xc7:
        return 3
      case 0xc8:
        return 4
      case 0xc9:
        return 6
      case 0xca:
        return 5
      case 0xcb:
        return 9
      case 0xcc:
        return 2
      case 0xcd:
        return 3
      case 0xce:
        return 5
      case 0xcf:
        return 9
      case 0xd0:
        return 2
      case 0xd1:
        return 3
      case 0xd2:
        return 5
      case 0xd3:
        return 9
      case 0xd4:
        return 3
      case 0xd5:
        return 4
      case 0xd6:
        return 6
      case 0xd7:
        return 10
      case 0xd8:
        return 18
      case 0xd9:
        return 2
      case 0xda:
        return 3
      case 0xdb:
        return 5
      case 0xde:
        return 3
      default:
        return -1
    }
  }

  function hasMinBufferSize (first, length) {
    var size = getSize(first)

    if (size !== -1 && length < size) {
      return false
    } else {
      return true
    }
  }

  function isValidDataSize (dataLength, bufLength, headerLength) {
    return bufLength >= headerLength + dataLength
  }

  function buildDecodeResult (value, bytesConsumed) {
    return {
      value: value,
      bytesConsumed: bytesConsumed
    }
  }

  function decode (buf) {
    if (!(buf instanceof bl)) {
      buf = bl().append(buf)
    }

    var result = tryDecode(buf)
    if (result) {
      buf.consume(result.bytesConsumed)
      return result.value
    } else {
      throw new IncompleteBufferError()
    }
  }

  function tryDecode (buf, offset) {
    offset = offset === undefined ? 0 : offset
    var bufLength = buf.length - offset
    if (bufLength <= 0) {
      return null
    }

    var first = buf.readUInt8(offset)
    var length
    var result = 0
    var type
    var bytePos

    if (!hasMinBufferSize(first, bufLength)) {
      return null
    }

    switch (first) {
      case 0xc0:
        return buildDecodeResult(null, 1)
      case 0xc2:
        return buildDecodeResult(false, 1)
      case 0xc3:
        return buildDecodeResult(true, 1)
      case 0xcc:
        // 1-byte unsigned int
        result = buf.readUInt8(offset + 1)
        return buildDecodeResult(result, 2)
      case 0xcd:
        // 2-bytes BE unsigned int
        result = buf.readUInt16BE(offset + 1)
        return buildDecodeResult(result, 3)
      case 0xce:
        // 4-bytes BE unsigned int
        result = buf.readUInt32BE(offset + 1)
        return buildDecodeResult(result, 5)
      case 0xcf:
        // 8-bytes BE unsigned int
        // Read long byte by byte, big-endian
        for (bytePos = 7; bytePos >= 0; bytePos--) {
          result += (buf.readUInt8(offset + bytePos + 1) * Math.pow(2, (8 * (7 - bytePos))))
        }
        return buildDecodeResult(result, 9)
      case 0xd0:
        // 1-byte signed int
        result = buf.readInt8(offset + 1)
        return buildDecodeResult(result, 2)
      case 0xd1:
        // 2-bytes signed int
        result = buf.readInt16BE(offset + 1)
        return buildDecodeResult(result, 3)
      case 0xd2:
        // 4-bytes signed int
        result = buf.readInt32BE(offset + 1)
        return buildDecodeResult(result, 5)
      case 0xd3:
        result = readInt64BE(buf.slice(offset + 1, offset + 9), 0)
        return buildDecodeResult(result, 9)
      case 0xca:
        // 4-bytes float
        result = buf.readFloatBE(offset + 1)
        return buildDecodeResult(result, 5)
      case 0xcb:
        // 8-bytes double
        result = buf.readDoubleBE(offset + 1)
        return buildDecodeResult(result, 9)
      case 0xd9:
        // strings up to 2^8 - 1 bytes
        length = buf.readUInt8(offset + 1)
        if (!isValidDataSize(length, bufLength, 2)) {
          return null
        }
        result = buf.toString('utf8', offset + 2, offset + 2 + length)
        return buildDecodeResult(result, 2 + length)
      case 0xda:
        // strings up to 2^16 - 2 bytes
        length = buf.readUInt16BE(offset + 1)
        if (!isValidDataSize(length, bufLength, 3)) {
          return null
        }
        result = buf.toString('utf8', offset + 3, offset + 3 + length)
        return buildDecodeResult(result, 3 + length)
      case 0xdb:
        // strings up to 2^32 - 4 bytes
        length = buf.readUInt32BE(offset + 1)
        if (!isValidDataSize(length, bufLength, 5)) {
          return null
        }
        result = buf.toString('utf8', offset + 5, offset + 5 + length)
        return buildDecodeResult(result, 5 + length)
      case 0xc4:
        // buffers up to 2^8 - 1 bytes
        length = buf.readUInt8(offset + 1)
        if (!isValidDataSize(length, bufLength, 2)) {
          return null
        }
        result = buf.slice(offset + 2, offset + 2 + length)
        return buildDecodeResult(result, 2 + length)
      case 0xc5:
        // buffers up to 2^16 - 1 bytes
        length = buf.readUInt16BE(offset + 1)
        if (!isValidDataSize(length, bufLength, 3)) {
          return null
        }
        result = buf.slice(offset + 3, offset + 3 + length)
        return buildDecodeResult(result, 3 + length)
      case 0xc6:
        // buffers up to 2^32 - 1 bytes
        length = buf.readUInt32BE(offset + 1)
        if (!isValidDataSize(length, bufLength, 5)) {
          return null
        }
        result = buf.slice(offset + 5, offset + 5 + length)
        return buildDecodeResult(result, 5 + length)
      case 0xdc:
        // array up to 2^16 elements - 2 bytes
        if (bufLength < 3) {
          return null
        }

        length = buf.readUInt16BE(offset + 1)
        return decodeArray(buf, offset, length, 3)
      case 0xdd:
        // array up to 2^32 elements - 4 bytes
        if (bufLength < 5) {
          return null
        }

        length = buf.readUInt32BE(offset + 1)
        return decodeArray(buf, offset, length, 5)
      case 0xde:
        // maps up to 2^16 elements - 2 bytes
        length = buf.readUInt16BE(offset + 1)
        return decodeMap(buf, offset, length, 3)
      case 0xdf:
        throw new Error('map too big to decode in JS')
      case 0xd4:
        return decodeFixExt(buf, offset, 1)
      case 0xd5:
        return decodeFixExt(buf, offset, 2)
      case 0xd6:
        return decodeFixExt(buf, offset, 4)
      case 0xd7:
        return decodeFixExt(buf, offset, 8)
      case 0xd8:
        return decodeFixExt(buf, offset, 16)
      case 0xc7:
        // ext up to 2^8 - 1 bytes
        length = buf.readUInt8(offset + 1)
        type = buf.readUInt8(offset + 2)
        if (!isValidDataSize(length, bufLength, 3)) {
          return null
        }
        return decodeExt(buf, offset, type, length, 3)
      case 0xc8:
        // ext up to 2^16 - 1 bytes
        length = buf.readUInt16BE(offset + 1)
        type = buf.readUInt8(offset + 3)
        if (!isValidDataSize(length, bufLength, 4)) {
          return null
        }
        return decodeExt(buf, offset, type, length, 4)
      case 0xc9:
        // ext up to 2^32 - 1 bytes
        length = buf.readUInt32BE(offset + 1)
        type = buf.readUInt8(offset + 5)
        if (!isValidDataSize(length, bufLength, 6)) {
          return null
        }
        return decodeExt(buf, offset, type, length, 6)
    }

    if ((first & 0xf0) === 0x90) {
      // we have an array with less than 15 elements
      length = first & 0x0f
      return decodeArray(buf, offset, length, 1)
    } else if ((first & 0xf0) === 0x80) {
      // we have a map with less than 15 elements
      length = first & 0x0f
      return decodeMap(buf, offset, length, 1)
    } else if ((first & 0xe0) === 0xa0) {
      // fixstr up to 31 bytes
      length = first & 0x1f
      if (isValidDataSize(length, bufLength, 1)) {
        result = buf.toString('utf8', offset + 1, offset + length + 1)
        return buildDecodeResult(result, length + 1)
      } else {
        return null
      }
    } else if (first >= 0xe0) {
      // 5 bits negative ints
      result = first - 0x100
      return buildDecodeResult(result, 1)
    } else if (first < 0x80) {
      // 7-bits positive ints
      return buildDecodeResult(first, 1)
    } else {
      throw new Error('not implemented yet')
    }
  }

  function readInt64BE (buf, offset) {
    var negate = (buf[offset] & 0x80) == 0x80 // eslint-disable-line

    if (negate) {
      var carry = 1
      for (var i = offset + 7; i >= offset; i--) {
        var v = (buf[i] ^ 0xff) + carry
        buf[i] = v & 0xff
        carry = v >> 8
      }
    }

    var hi = buf.readUInt32BE(offset + 0)
    var lo = buf.readUInt32BE(offset + 4)
    return (hi * 4294967296 + lo) * (negate ? -1 : +1)
  }

  function decodeArray (buf, offset, length, headerLength) {
    var result = []
    var i
    var totalBytesConsumed = 0

    offset += headerLength
    for (i = 0; i < length; i++) {
      var decodeResult = tryDecode(buf, offset)
      if (decodeResult) {
        result.push(decodeResult.value)
        offset += decodeResult.bytesConsumed
        totalBytesConsumed += decodeResult.bytesConsumed
      } else {
        return null
      }
    }
    return buildDecodeResult(result, headerLength + totalBytesConsumed)
  }

  function decodeMap (buf, offset, length, headerLength) {
    var result = {}
    var key
    var i
    var totalBytesConsumed = 0

    offset += headerLength
    for (i = 0; i < length; i++) {
      var keyResult = tryDecode(buf, offset)
      if (keyResult) {
        offset += keyResult.bytesConsumed
        var valueResult = tryDecode(buf, offset)
        if (valueResult) {
          key = keyResult.value
          result[key] = valueResult.value
          offset += valueResult.bytesConsumed
          totalBytesConsumed += (keyResult.bytesConsumed + valueResult.bytesConsumed)
        } else {
          return null
        }
      } else {
        return null
      }
    }
    return buildDecodeResult(result, headerLength + totalBytesConsumed)
  }

  function decodeFixExt (buf, offset, size) {
    var type = buf.readInt8(offset + 1) // Signed
    return decodeExt(buf, offset, type, size, 2)
  }
  function decodeTimestamp (buf, size, headerSize) {
    var seconds, nanoseconds
    nanoseconds = 0

    switch (size) {
      case 4:
          // timestamp 32 stores the number of seconds that have elapsed since 1970-01-01 00:00:00 UTC in an 32-bit unsigned integer
        seconds = buf.readUInt32BE()
        break

      case 8: // Timestamp 64 stores the number of seconds and nanoseconds that have elapsed
                // since 1970-01-01 00:00:00 UTC in 32-bit unsigned integers, split 30/34 bits
        var upper = buf.readUInt32BE()
        var lower = buf.readUInt32BE(4)
        nanoseconds = upper / 4
        seconds = ((upper & 0x03) * Math.pow(2, 32)) + lower // If we use bitwise operators, we get truncated to 32bits
        break

      case 12:
        throw new Error('timestamp 96 is not yet implemented')
    }

    var millis = (seconds * 1000) + Math.round(nanoseconds / 1E6)
    return buildDecodeResult(new Date(millis), size + headerSize)
  }

  function decodeExt (buf, offset, type, size, headerSize) {
    var i,
      toDecode

    offset += headerSize

    // Pre-defined
    if (type < 0) { // Reserved for future extensions
      switch (type) {
        case -1: // Tiemstamp https://github.com/msgpack/msgpack/blob/master/spec.md#timestamp-extension-type
          toDecode = buf.slice(offset, offset + size)
          return decodeTimestamp(toDecode, size, headerSize)
      }
    }

    for (i = 0; i < decodingTypes.length; i++) {
      if (type === decodingTypes[i].type) {
        toDecode = buf.slice(offset, offset + size)
        var value = decodingTypes[i].decode(toDecode)
        return buildDecodeResult(value, headerSize + size)
      }
    }

    throw new Error('unable to find ext type ' + type)
  }
}

module.exports.IncompleteBufferError = IncompleteBufferError

},{"bl":10,"util":45}],27:[function(require,module,exports){
'use strict'

var Buffer = require('safe-buffer').Buffer
var bl = require('bl')
var TOLERANCE = 0.1

module.exports = function buildEncode (encodingTypes, forceFloat64, compatibilityMode, disableTimestampEncoding) {
  function encode (obj, avoidSlice) {
    var buf,
      len

    if (obj === undefined) {
      throw new Error('undefined is not encodable in msgpack!')
    } else if (obj === null) {
      buf = Buffer.allocUnsafe(1)
      buf[0] = 0xc0
    } else if (obj === true) {
      buf = Buffer.allocUnsafe(1)
      buf[0] = 0xc3
    } else if (obj === false) {
      buf = Buffer.allocUnsafe(1)
      buf[0] = 0xc2
    } else if (typeof obj === 'string') {
      len = Buffer.byteLength(obj)
      if (len < 32) {
        buf = Buffer.allocUnsafe(1 + len)
        buf[0] = 0xa0 | len
        if (len > 0) {
          buf.write(obj, 1)
        }
      } else if (len <= 0xff && !compatibilityMode) {
        // str8, but only when not in compatibility mode
        buf = Buffer.allocUnsafe(2 + len)
        buf[0] = 0xd9
        buf[1] = len
        buf.write(obj, 2)
      } else if (len <= 0xffff) {
        buf = Buffer.allocUnsafe(3 + len)
        buf[0] = 0xda
        buf.writeUInt16BE(len, 1)
        buf.write(obj, 3)
      } else {
        buf = Buffer.allocUnsafe(5 + len)
        buf[0] = 0xdb
        buf.writeUInt32BE(len, 1)
        buf.write(obj, 5)
      }
    } else if (obj && (obj.readUInt32LE || obj instanceof Uint8Array)) {
      if (obj instanceof Uint8Array) {
        obj = Buffer.from(obj)
      }
      // weird hack to support Buffer
      // and Buffer-like objects
      if (obj.length <= 0xff) {
        buf = Buffer.allocUnsafe(2)
        buf[0] = 0xc4
        buf[1] = obj.length
      } else if (obj.length <= 0xffff) {
        buf = Buffer.allocUnsafe(3)
        buf[0] = 0xc5
        buf.writeUInt16BE(obj.length, 1)
      } else {
        buf = Buffer.allocUnsafe(5)
        buf[0] = 0xc6
        buf.writeUInt32BE(obj.length, 1)
      }

      buf = bl([buf, obj])
    } else if (Array.isArray(obj)) {
      if (obj.length < 16) {
        buf = Buffer.allocUnsafe(1)
        buf[0] = 0x90 | obj.length
      } else if (obj.length < 65536) {
        buf = Buffer.allocUnsafe(3)
        buf[0] = 0xdc
        buf.writeUInt16BE(obj.length, 1)
      } else {
        buf = Buffer.allocUnsafe(5)
        buf[0] = 0xdd
        buf.writeUInt32BE(obj.length, 1)
      }

      buf = obj.reduce(function (acc, obj) {
        acc.append(encode(obj, true))
        return acc
      }, bl().append(buf))
    } else if (!disableTimestampEncoding && typeof obj.getDate === 'function') {
      return encodeDate(obj)
    } else if (typeof obj === 'object') {
      buf = encodeExt(obj) || encodeObject(obj)
    } else if (typeof obj === 'number') {
      if (isFloat(obj)) {
        return encodeFloat(obj, forceFloat64)
      } else if (obj >= 0) {
        if (obj < 128) {
          buf = Buffer.allocUnsafe(1)
          buf[0] = obj
        } else if (obj < 256) {
          buf = Buffer.allocUnsafe(2)
          buf[0] = 0xcc
          buf[1] = obj
        } else if (obj < 65536) {
          buf = Buffer.allocUnsafe(3)
          buf[0] = 0xcd
          buf.writeUInt16BE(obj, 1)
        } else if (obj <= 0xffffffff) {
          buf = Buffer.allocUnsafe(5)
          buf[0] = 0xce
          buf.writeUInt32BE(obj, 1)
        } else if (obj <= 9007199254740991) {
          buf = Buffer.allocUnsafe(9)
          buf[0] = 0xcf
          write64BitUint(buf, obj)
        } else {
          return encodeFloat(obj, true)
        }
      } else {
        if (obj >= -32) {
          buf = Buffer.allocUnsafe(1)
          buf[0] = 0x100 + obj
        } else if (obj >= -128) {
          buf = Buffer.allocUnsafe(2)
          buf[0] = 0xd0
          buf.writeInt8(obj, 1)
        } else if (obj >= -32768) {
          buf = Buffer.allocUnsafe(3)
          buf[0] = 0xd1
          buf.writeInt16BE(obj, 1)
        } else if (obj > -214748365) {
          buf = Buffer.allocUnsafe(5)
          buf[0] = 0xd2
          buf.writeInt32BE(obj, 1)
        } else if (obj >= -9007199254740991) {
          buf = Buffer.allocUnsafe(9)
          buf[0] = 0xd3
          write64BitInt(buf, 1, obj)
        } else {
          return encodeFloat(obj, true)
        }
      }
    }

    if (!buf) {
      throw new Error('not implemented yet')
    }

    if (avoidSlice) {
      return buf
    } else {
      return buf.slice()
    }
  }

  function encodeDate (dt) {
    var encoded
    var millis = dt * 1
    var seconds = Math.floor(millis / 1000)
    var nanos = (millis - (seconds * 1000)) * 1E6

    if (nanos || seconds > 0xFFFFFFFF) {
        // Timestamp64
      encoded = new Buffer(10)
      encoded[0] = 0xd7
      encoded[1] = -1

      var upperNanos = ((nanos * 4))
      var upperSeconds = seconds / Math.pow(2, 32)
      var upper = (upperNanos + upperSeconds) & 0xFFFFFFFF
      var lower = seconds & 0xFFFFFFFF

      encoded.writeInt32BE(upper, 2)
      encoded.writeInt32BE(lower, 6)
    } else {
        // Timestamp32
      encoded = new Buffer(6)
      encoded[0] = 0xd6
      encoded[1] = -1
      encoded.writeUInt32BE(Math.floor(millis / 1000), 2)
    }
    return bl().append(encoded)
  }

  function encodeExt (obj) {
    var i
    var encoded
    var length = -1
    var headers = []

    for (i = 0; i < encodingTypes.length; i++) {
      if (encodingTypes[i].check(obj)) {
        encoded = encodingTypes[i].encode(obj)
        break
      }
    }

    if (!encoded) {
      return null
    }

    // we subtract 1 because the length does not
    // include the type
    length = encoded.length - 1

    if (length === 1) {
      headers.push(0xd4)
    } else if (length === 2) {
      headers.push(0xd5)
    } else if (length === 4) {
      headers.push(0xd6)
    } else if (length === 8) {
      headers.push(0xd7)
    } else if (length === 16) {
      headers.push(0xd8)
    } else if (length < 256) {
      headers.push(0xc7)
      headers.push(length)
    } else if (length < 0x10000) {
      headers.push(0xc8)
      headers.push(length >> 8)
      headers.push(length & 0x00ff)
    } else {
      headers.push(0xc9)
      headers.push(length >> 24)
      headers.push((length >> 16) & 0x000000ff)
      headers.push((length >> 8) & 0x000000ff)
      headers.push(length & 0x000000ff)
    }

    return bl().append(Buffer.from(headers)).append(encoded)
  }

  function encodeObject (obj) {
    var acc = []
    var length = 0
    var key
    var header

    for (key in obj) {
      if (obj.hasOwnProperty(key) &&
        obj[key] !== undefined &&
        typeof obj[key] !== 'function') {
        ++length
        acc.push(encode(key, true))
        acc.push(encode(obj[key], true))
      }
    }

    if (length < 16) {
      header = Buffer.allocUnsafe(1)
      header[0] = 0x80 | length
    } else {
      header = Buffer.allocUnsafe(3)
      header[0] = 0xde
      header.writeUInt16BE(length, 1)
    }

    acc.unshift(header)

    var result = acc.reduce(function (list, buf) {
      return list.append(buf)
    }, bl())

    return result
  }

  return encode
}

function write64BitUint (buf, obj) {
  // Write long byte by byte, in big-endian order
  for (var currByte = 7; currByte >= 0; currByte--) {
    buf[currByte + 1] = (obj & 0xff)
    obj = obj / 256
  }
}

function write64BitInt (buf, offset, num) {
  var negate = num < 0

  if (negate) {
    num = Math.abs(num)
  }

  var lo = num % 4294967296
  var hi = num / 4294967296
  buf.writeUInt32BE(Math.floor(hi), offset + 0)
  buf.writeUInt32BE(lo, offset + 4)

  if (negate) {
    var carry = 1
    for (var i = offset + 7; i >= offset; i--) {
      var v = (buf[i] ^ 0xff) + carry
      buf[i] = v & 0xff
      carry = v >> 8
    }
  }
}

function isFloat (n) {
  return n !== Math.floor(n)
}

function encodeFloat (obj, forceFloat64) {
  var buf

  buf = Buffer.allocUnsafe(5)
  buf[0] = 0xca
  buf.writeFloatBE(obj, 1)

  // FIXME is there a way to check if a
  // value fits in a float?
  if (forceFloat64 || Math.abs(obj - buf.readFloatBE(1)) > TOLERANCE) {
    buf = Buffer.allocUnsafe(9)
    buf[0] = 0xcb
    buf.writeDoubleBE(obj, 1)
  }

  return buf
}

},{"bl":10,"safe-buffer":40}],28:[function(require,module,exports){
'use strict'

var Transform = require('readable-stream').Transform
var inherits = require('inherits')
var bl = require('bl')

function Base (opts) {
  opts = opts || {}

  opts.objectMode = true
  opts.highWaterMark = 16

  Transform.call(this, opts)

  this._msgpack = opts.msgpack
}

inherits(Base, Transform)

function Encoder (opts) {
  if (!(this instanceof Encoder)) {
    opts = opts || {}
    opts.msgpack = this
    return new Encoder(opts)
  }

  Base.call(this, opts)
}

inherits(Encoder, Base)

Encoder.prototype._transform = function (obj, enc, done) {
  var buf = null

  try {
    buf = this._msgpack.encode(obj).slice(0)
  } catch (err) {
    this.emit('error', err)
    return done()
  }

  this.push(buf)
  done()
}

function Decoder (opts) {
  if (!(this instanceof Decoder)) {
    opts = opts || {}
    opts.msgpack = this
    return new Decoder(opts)
  }

  Base.call(this, opts)

  this._chunks = bl()
}

inherits(Decoder, Base)

Decoder.prototype._transform = function (buf, enc, done) {
  if (buf) {
    this._chunks.append(buf)
  }

  try {
    var result = this._msgpack.decode(this._chunks)
    this.push(result)
  } catch (err) {
    if (err instanceof this._msgpack.IncompleteBufferError) {
      done()
    } else {
      this.emit('error', err)
    }
    return
  }

  if (this._chunks.length > 0) {
    this._transform(null, enc, done)
  } else {
    done()
  }
}

module.exports.decoder = Decoder
module.exports.encoder = Encoder

},{"bl":10,"inherits":20,"readable-stream":39}],29:[function(require,module,exports){
(function (process){
'use strict';

if (!process.version ||
    process.version.indexOf('v0.') === 0 ||
    process.version.indexOf('v1.') === 0 && process.version.indexOf('v1.8.') !== 0) {
  module.exports = nextTick;
} else {
  module.exports = process.nextTick;
}

function nextTick(fn, arg1, arg2, arg3) {
  if (typeof fn !== 'function') {
    throw new TypeError('"callback" argument must be a function');
  }
  var len = arguments.length;
  var args, i;
  switch (len) {
  case 0:
  case 1:
    return process.nextTick(fn);
  case 2:
    return process.nextTick(function afterTickOne() {
      fn.call(null, arg1);
    });
  case 3:
    return process.nextTick(function afterTickTwo() {
      fn.call(null, arg1, arg2);
    });
  case 4:
    return process.nextTick(function afterTickThree() {
      fn.call(null, arg1, arg2, arg3);
    });
  default:
    args = new Array(len - 1);
    i = 0;
    while (i < args.length) {
      args[i++] = arguments[i];
    }
    return process.nextTick(function afterTick() {
      fn.apply(null, args);
    });
  }
}

}).call(this,require('_process'))
},{"_process":18}],30:[function(require,module,exports){
module.exports = require('./lib/_stream_duplex.js');

},{"./lib/_stream_duplex.js":31}],31:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

// a duplex stream is just a stream that is both readable and writable.
// Since JS doesn't have multiple prototypal inheritance, this class
// prototypally inherits from Readable, and then parasitically from
// Writable.

'use strict';

/*<replacement>*/

var processNextTick = require('process-nextick-args');
/*</replacement>*/

/*<replacement>*/
var objectKeys = Object.keys || function (obj) {
  var keys = [];
  for (var key in obj) {
    keys.push(key);
  }return keys;
};
/*</replacement>*/

module.exports = Duplex;

/*<replacement>*/
var util = require('core-util-is');
util.inherits = require('inherits');
/*</replacement>*/

var Readable = require('./_stream_readable');
var Writable = require('./_stream_writable');

util.inherits(Duplex, Readable);

var keys = objectKeys(Writable.prototype);
for (var v = 0; v < keys.length; v++) {
  var method = keys[v];
  if (!Duplex.prototype[method]) Duplex.prototype[method] = Writable.prototype[method];
}

function Duplex(options) {
  if (!(this instanceof Duplex)) return new Duplex(options);

  Readable.call(this, options);
  Writable.call(this, options);

  if (options && options.readable === false) this.readable = false;

  if (options && options.writable === false) this.writable = false;

  this.allowHalfOpen = true;
  if (options && options.allowHalfOpen === false) this.allowHalfOpen = false;

  this.once('end', onend);
}

// the no-half-open enforcer
function onend() {
  // if we allow half-open state, or if the writable side ended,
  // then we're ok.
  if (this.allowHalfOpen || this._writableState.ended) return;

  // no more data can be written.
  // But allow more writes to happen in this tick.
  processNextTick(onEndNT, this);
}

function onEndNT(self) {
  self.end();
}

Object.defineProperty(Duplex.prototype, 'destroyed', {
  get: function () {
    if (this._readableState === undefined || this._writableState === undefined) {
      return false;
    }
    return this._readableState.destroyed && this._writableState.destroyed;
  },
  set: function (value) {
    // we ignore the value if the stream
    // has not been initialized yet
    if (this._readableState === undefined || this._writableState === undefined) {
      return;
    }

    // backward compatibility, the user is explicitly
    // managing destroyed
    this._readableState.destroyed = value;
    this._writableState.destroyed = value;
  }
});

Duplex.prototype._destroy = function (err, cb) {
  this.push(null);
  this.end();

  processNextTick(cb, err);
};

function forEach(xs, f) {
  for (var i = 0, l = xs.length; i < l; i++) {
    f(xs[i], i);
  }
}
},{"./_stream_readable":33,"./_stream_writable":35,"core-util-is":14,"inherits":20,"process-nextick-args":29}],32:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

// a passthrough stream.
// basically just the most minimal sort of Transform stream.
// Every written chunk gets output as-is.

'use strict';

module.exports = PassThrough;

var Transform = require('./_stream_transform');

/*<replacement>*/
var util = require('core-util-is');
util.inherits = require('inherits');
/*</replacement>*/

util.inherits(PassThrough, Transform);

function PassThrough(options) {
  if (!(this instanceof PassThrough)) return new PassThrough(options);

  Transform.call(this, options);
}

PassThrough.prototype._transform = function (chunk, encoding, cb) {
  cb(null, chunk);
};
},{"./_stream_transform":34,"core-util-is":14,"inherits":20}],33:[function(require,module,exports){
(function (process,global){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

/*<replacement>*/

var processNextTick = require('process-nextick-args');
/*</replacement>*/

module.exports = Readable;

/*<replacement>*/
var isArray = require('isarray');
/*</replacement>*/

/*<replacement>*/
var Duplex;
/*</replacement>*/

Readable.ReadableState = ReadableState;

/*<replacement>*/
var EE = require('events').EventEmitter;

var EElistenerCount = function (emitter, type) {
  return emitter.listeners(type).length;
};
/*</replacement>*/

/*<replacement>*/
var Stream = require('./internal/streams/stream');
/*</replacement>*/

// TODO(bmeurer): Change this back to const once hole checks are
// properly optimized away early in Ignition+TurboFan.
/*<replacement>*/
var Buffer = require('safe-buffer').Buffer;
var OurUint8Array = global.Uint8Array || function () {};
function _uint8ArrayToBuffer(chunk) {
  return Buffer.from(chunk);
}
function _isUint8Array(obj) {
  return Buffer.isBuffer(obj) || obj instanceof OurUint8Array;
}
/*</replacement>*/

/*<replacement>*/
var util = require('core-util-is');
util.inherits = require('inherits');
/*</replacement>*/

/*<replacement>*/
var debugUtil = require('util');
var debug = void 0;
if (debugUtil && debugUtil.debuglog) {
  debug = debugUtil.debuglog('stream');
} else {
  debug = function () {};
}
/*</replacement>*/

var BufferList = require('./internal/streams/BufferList');
var destroyImpl = require('./internal/streams/destroy');
var StringDecoder;

util.inherits(Readable, Stream);

var kProxyEvents = ['error', 'close', 'destroy', 'pause', 'resume'];

function prependListener(emitter, event, fn) {
  // Sadly this is not cacheable as some libraries bundle their own
  // event emitter implementation with them.
  if (typeof emitter.prependListener === 'function') {
    return emitter.prependListener(event, fn);
  } else {
    // This is a hack to make sure that our error handler is attached before any
    // userland ones.  NEVER DO THIS. This is here only because this code needs
    // to continue to work with older versions of Node.js that do not include
    // the prependListener() method. The goal is to eventually remove this hack.
    if (!emitter._events || !emitter._events[event]) emitter.on(event, fn);else if (isArray(emitter._events[event])) emitter._events[event].unshift(fn);else emitter._events[event] = [fn, emitter._events[event]];
  }
}

function ReadableState(options, stream) {
  Duplex = Duplex || require('./_stream_duplex');

  options = options || {};

  // object stream flag. Used to make read(n) ignore n and to
  // make all the buffer merging and length checks go away
  this.objectMode = !!options.objectMode;

  if (stream instanceof Duplex) this.objectMode = this.objectMode || !!options.readableObjectMode;

  // the point at which it stops calling _read() to fill the buffer
  // Note: 0 is a valid value, means "don't call _read preemptively ever"
  var hwm = options.highWaterMark;
  var defaultHwm = this.objectMode ? 16 : 16 * 1024;
  this.highWaterMark = hwm || hwm === 0 ? hwm : defaultHwm;

  // cast to ints.
  this.highWaterMark = Math.floor(this.highWaterMark);

  // A linked list is used to store data chunks instead of an array because the
  // linked list can remove elements from the beginning faster than
  // array.shift()
  this.buffer = new BufferList();
  this.length = 0;
  this.pipes = null;
  this.pipesCount = 0;
  this.flowing = null;
  this.ended = false;
  this.endEmitted = false;
  this.reading = false;

  // a flag to be able to tell if the event 'readable'/'data' is emitted
  // immediately, or on a later tick.  We set this to true at first, because
  // any actions that shouldn't happen until "later" should generally also
  // not happen before the first read call.
  this.sync = true;

  // whenever we return null, then we set a flag to say
  // that we're awaiting a 'readable' event emission.
  this.needReadable = false;
  this.emittedReadable = false;
  this.readableListening = false;
  this.resumeScheduled = false;

  // has it been destroyed
  this.destroyed = false;

  // Crypto is kind of old and crusty.  Historically, its default string
  // encoding is 'binary' so we have to make this configurable.
  // Everything else in the universe uses 'utf8', though.
  this.defaultEncoding = options.defaultEncoding || 'utf8';

  // the number of writers that are awaiting a drain event in .pipe()s
  this.awaitDrain = 0;

  // if true, a maybeReadMore has been scheduled
  this.readingMore = false;

  this.decoder = null;
  this.encoding = null;
  if (options.encoding) {
    if (!StringDecoder) StringDecoder = require('string_decoder/').StringDecoder;
    this.decoder = new StringDecoder(options.encoding);
    this.encoding = options.encoding;
  }
}

function Readable(options) {
  Duplex = Duplex || require('./_stream_duplex');

  if (!(this instanceof Readable)) return new Readable(options);

  this._readableState = new ReadableState(options, this);

  // legacy
  this.readable = true;

  if (options) {
    if (typeof options.read === 'function') this._read = options.read;

    if (typeof options.destroy === 'function') this._destroy = options.destroy;
  }

  Stream.call(this);
}

Object.defineProperty(Readable.prototype, 'destroyed', {
  get: function () {
    if (this._readableState === undefined) {
      return false;
    }
    return this._readableState.destroyed;
  },
  set: function (value) {
    // we ignore the value if the stream
    // has not been initialized yet
    if (!this._readableState) {
      return;
    }

    // backward compatibility, the user is explicitly
    // managing destroyed
    this._readableState.destroyed = value;
  }
});

Readable.prototype.destroy = destroyImpl.destroy;
Readable.prototype._undestroy = destroyImpl.undestroy;
Readable.prototype._destroy = function (err, cb) {
  this.push(null);
  cb(err);
};

// Manually shove something into the read() buffer.
// This returns true if the highWaterMark has not been hit yet,
// similar to how Writable.write() returns true if you should
// write() some more.
Readable.prototype.push = function (chunk, encoding) {
  var state = this._readableState;
  var skipChunkCheck;

  if (!state.objectMode) {
    if (typeof chunk === 'string') {
      encoding = encoding || state.defaultEncoding;
      if (encoding !== state.encoding) {
        chunk = Buffer.from(chunk, encoding);
        encoding = '';
      }
      skipChunkCheck = true;
    }
  } else {
    skipChunkCheck = true;
  }

  return readableAddChunk(this, chunk, encoding, false, skipChunkCheck);
};

// Unshift should *always* be something directly out of read()
Readable.prototype.unshift = function (chunk) {
  return readableAddChunk(this, chunk, null, true, false);
};

function readableAddChunk(stream, chunk, encoding, addToFront, skipChunkCheck) {
  var state = stream._readableState;
  if (chunk === null) {
    state.reading = false;
    onEofChunk(stream, state);
  } else {
    var er;
    if (!skipChunkCheck) er = chunkInvalid(state, chunk);
    if (er) {
      stream.emit('error', er);
    } else if (state.objectMode || chunk && chunk.length > 0) {
      if (typeof chunk !== 'string' && !state.objectMode && Object.getPrototypeOf(chunk) !== Buffer.prototype) {
        chunk = _uint8ArrayToBuffer(chunk);
      }

      if (addToFront) {
        if (state.endEmitted) stream.emit('error', new Error('stream.unshift() after end event'));else addChunk(stream, state, chunk, true);
      } else if (state.ended) {
        stream.emit('error', new Error('stream.push() after EOF'));
      } else {
        state.reading = false;
        if (state.decoder && !encoding) {
          chunk = state.decoder.write(chunk);
          if (state.objectMode || chunk.length !== 0) addChunk(stream, state, chunk, false);else maybeReadMore(stream, state);
        } else {
          addChunk(stream, state, chunk, false);
        }
      }
    } else if (!addToFront) {
      state.reading = false;
    }
  }

  return needMoreData(state);
}

function addChunk(stream, state, chunk, addToFront) {
  if (state.flowing && state.length === 0 && !state.sync) {
    stream.emit('data', chunk);
    stream.read(0);
  } else {
    // update the buffer info.
    state.length += state.objectMode ? 1 : chunk.length;
    if (addToFront) state.buffer.unshift(chunk);else state.buffer.push(chunk);

    if (state.needReadable) emitReadable(stream);
  }
  maybeReadMore(stream, state);
}

function chunkInvalid(state, chunk) {
  var er;
  if (!_isUint8Array(chunk) && typeof chunk !== 'string' && chunk !== undefined && !state.objectMode) {
    er = new TypeError('Invalid non-string/buffer chunk');
  }
  return er;
}

// if it's past the high water mark, we can push in some more.
// Also, if we have no data yet, we can stand some
// more bytes.  This is to work around cases where hwm=0,
// such as the repl.  Also, if the push() triggered a
// readable event, and the user called read(largeNumber) such that
// needReadable was set, then we ought to push more, so that another
// 'readable' event will be triggered.
function needMoreData(state) {
  return !state.ended && (state.needReadable || state.length < state.highWaterMark || state.length === 0);
}

Readable.prototype.isPaused = function () {
  return this._readableState.flowing === false;
};

// backwards compatibility.
Readable.prototype.setEncoding = function (enc) {
  if (!StringDecoder) StringDecoder = require('string_decoder/').StringDecoder;
  this._readableState.decoder = new StringDecoder(enc);
  this._readableState.encoding = enc;
  return this;
};

// Don't raise the hwm > 8MB
var MAX_HWM = 0x800000;
function computeNewHighWaterMark(n) {
  if (n >= MAX_HWM) {
    n = MAX_HWM;
  } else {
    // Get the next highest power of 2 to prevent increasing hwm excessively in
    // tiny amounts
    n--;
    n |= n >>> 1;
    n |= n >>> 2;
    n |= n >>> 4;
    n |= n >>> 8;
    n |= n >>> 16;
    n++;
  }
  return n;
}

// This function is designed to be inlinable, so please take care when making
// changes to the function body.
function howMuchToRead(n, state) {
  if (n <= 0 || state.length === 0 && state.ended) return 0;
  if (state.objectMode) return 1;
  if (n !== n) {
    // Only flow one buffer at a time
    if (state.flowing && state.length) return state.buffer.head.data.length;else return state.length;
  }
  // If we're asking for more than the current hwm, then raise the hwm.
  if (n > state.highWaterMark) state.highWaterMark = computeNewHighWaterMark(n);
  if (n <= state.length) return n;
  // Don't have enough
  if (!state.ended) {
    state.needReadable = true;
    return 0;
  }
  return state.length;
}

// you can override either this method, or the async _read(n) below.
Readable.prototype.read = function (n) {
  debug('read', n);
  n = parseInt(n, 10);
  var state = this._readableState;
  var nOrig = n;

  if (n !== 0) state.emittedReadable = false;

  // if we're doing read(0) to trigger a readable event, but we
  // already have a bunch of data in the buffer, then just trigger
  // the 'readable' event and move on.
  if (n === 0 && state.needReadable && (state.length >= state.highWaterMark || state.ended)) {
    debug('read: emitReadable', state.length, state.ended);
    if (state.length === 0 && state.ended) endReadable(this);else emitReadable(this);
    return null;
  }

  n = howMuchToRead(n, state);

  // if we've ended, and we're now clear, then finish it up.
  if (n === 0 && state.ended) {
    if (state.length === 0) endReadable(this);
    return null;
  }

  // All the actual chunk generation logic needs to be
  // *below* the call to _read.  The reason is that in certain
  // synthetic stream cases, such as passthrough streams, _read
  // may be a completely synchronous operation which may change
  // the state of the read buffer, providing enough data when
  // before there was *not* enough.
  //
  // So, the steps are:
  // 1. Figure out what the state of things will be after we do
  // a read from the buffer.
  //
  // 2. If that resulting state will trigger a _read, then call _read.
  // Note that this may be asynchronous, or synchronous.  Yes, it is
  // deeply ugly to write APIs this way, but that still doesn't mean
  // that the Readable class should behave improperly, as streams are
  // designed to be sync/async agnostic.
  // Take note if the _read call is sync or async (ie, if the read call
  // has returned yet), so that we know whether or not it's safe to emit
  // 'readable' etc.
  //
  // 3. Actually pull the requested chunks out of the buffer and return.

  // if we need a readable event, then we need to do some reading.
  var doRead = state.needReadable;
  debug('need readable', doRead);

  // if we currently have less than the highWaterMark, then also read some
  if (state.length === 0 || state.length - n < state.highWaterMark) {
    doRead = true;
    debug('length less than watermark', doRead);
  }

  // however, if we've ended, then there's no point, and if we're already
  // reading, then it's unnecessary.
  if (state.ended || state.reading) {
    doRead = false;
    debug('reading or ended', doRead);
  } else if (doRead) {
    debug('do read');
    state.reading = true;
    state.sync = true;
    // if the length is currently zero, then we *need* a readable event.
    if (state.length === 0) state.needReadable = true;
    // call internal read method
    this._read(state.highWaterMark);
    state.sync = false;
    // If _read pushed data synchronously, then `reading` will be false,
    // and we need to re-evaluate how much data we can return to the user.
    if (!state.reading) n = howMuchToRead(nOrig, state);
  }

  var ret;
  if (n > 0) ret = fromList(n, state);else ret = null;

  if (ret === null) {
    state.needReadable = true;
    n = 0;
  } else {
    state.length -= n;
  }

  if (state.length === 0) {
    // If we have nothing in the buffer, then we want to know
    // as soon as we *do* get something into the buffer.
    if (!state.ended) state.needReadable = true;

    // If we tried to read() past the EOF, then emit end on the next tick.
    if (nOrig !== n && state.ended) endReadable(this);
  }

  if (ret !== null) this.emit('data', ret);

  return ret;
};

function onEofChunk(stream, state) {
  if (state.ended) return;
  if (state.decoder) {
    var chunk = state.decoder.end();
    if (chunk && chunk.length) {
      state.buffer.push(chunk);
      state.length += state.objectMode ? 1 : chunk.length;
    }
  }
  state.ended = true;

  // emit 'readable' now to make sure it gets picked up.
  emitReadable(stream);
}

// Don't emit readable right away in sync mode, because this can trigger
// another read() call => stack overflow.  This way, it might trigger
// a nextTick recursion warning, but that's not so bad.
function emitReadable(stream) {
  var state = stream._readableState;
  state.needReadable = false;
  if (!state.emittedReadable) {
    debug('emitReadable', state.flowing);
    state.emittedReadable = true;
    if (state.sync) processNextTick(emitReadable_, stream);else emitReadable_(stream);
  }
}

function emitReadable_(stream) {
  debug('emit readable');
  stream.emit('readable');
  flow(stream);
}

// at this point, the user has presumably seen the 'readable' event,
// and called read() to consume some data.  that may have triggered
// in turn another _read(n) call, in which case reading = true if
// it's in progress.
// However, if we're not ended, or reading, and the length < hwm,
// then go ahead and try to read some more preemptively.
function maybeReadMore(stream, state) {
  if (!state.readingMore) {
    state.readingMore = true;
    processNextTick(maybeReadMore_, stream, state);
  }
}

function maybeReadMore_(stream, state) {
  var len = state.length;
  while (!state.reading && !state.flowing && !state.ended && state.length < state.highWaterMark) {
    debug('maybeReadMore read 0');
    stream.read(0);
    if (len === state.length)
      // didn't get any data, stop spinning.
      break;else len = state.length;
  }
  state.readingMore = false;
}

// abstract method.  to be overridden in specific implementation classes.
// call cb(er, data) where data is <= n in length.
// for virtual (non-string, non-buffer) streams, "length" is somewhat
// arbitrary, and perhaps not very meaningful.
Readable.prototype._read = function (n) {
  this.emit('error', new Error('_read() is not implemented'));
};

Readable.prototype.pipe = function (dest, pipeOpts) {
  var src = this;
  var state = this._readableState;

  switch (state.pipesCount) {
    case 0:
      state.pipes = dest;
      break;
    case 1:
      state.pipes = [state.pipes, dest];
      break;
    default:
      state.pipes.push(dest);
      break;
  }
  state.pipesCount += 1;
  debug('pipe count=%d opts=%j', state.pipesCount, pipeOpts);

  var doEnd = (!pipeOpts || pipeOpts.end !== false) && dest !== process.stdout && dest !== process.stderr;

  var endFn = doEnd ? onend : unpipe;
  if (state.endEmitted) processNextTick(endFn);else src.once('end', endFn);

  dest.on('unpipe', onunpipe);
  function onunpipe(readable, unpipeInfo) {
    debug('onunpipe');
    if (readable === src) {
      if (unpipeInfo && unpipeInfo.hasUnpiped === false) {
        unpipeInfo.hasUnpiped = true;
        cleanup();
      }
    }
  }

  function onend() {
    debug('onend');
    dest.end();
  }

  // when the dest drains, it reduces the awaitDrain counter
  // on the source.  This would be more elegant with a .once()
  // handler in flow(), but adding and removing repeatedly is
  // too slow.
  var ondrain = pipeOnDrain(src);
  dest.on('drain', ondrain);

  var cleanedUp = false;
  function cleanup() {
    debug('cleanup');
    // cleanup event handlers once the pipe is broken
    dest.removeListener('close', onclose);
    dest.removeListener('finish', onfinish);
    dest.removeListener('drain', ondrain);
    dest.removeListener('error', onerror);
    dest.removeListener('unpipe', onunpipe);
    src.removeListener('end', onend);
    src.removeListener('end', unpipe);
    src.removeListener('data', ondata);

    cleanedUp = true;

    // if the reader is waiting for a drain event from this
    // specific writer, then it would cause it to never start
    // flowing again.
    // So, if this is awaiting a drain, then we just call it now.
    // If we don't know, then assume that we are waiting for one.
    if (state.awaitDrain && (!dest._writableState || dest._writableState.needDrain)) ondrain();
  }

  // If the user pushes more data while we're writing to dest then we'll end up
  // in ondata again. However, we only want to increase awaitDrain once because
  // dest will only emit one 'drain' event for the multiple writes.
  // => Introduce a guard on increasing awaitDrain.
  var increasedAwaitDrain = false;
  src.on('data', ondata);
  function ondata(chunk) {
    debug('ondata');
    increasedAwaitDrain = false;
    var ret = dest.write(chunk);
    if (false === ret && !increasedAwaitDrain) {
      // If the user unpiped during `dest.write()`, it is possible
      // to get stuck in a permanently paused state if that write
      // also returned false.
      // => Check whether `dest` is still a piping destination.
      if ((state.pipesCount === 1 && state.pipes === dest || state.pipesCount > 1 && indexOf(state.pipes, dest) !== -1) && !cleanedUp) {
        debug('false write response, pause', src._readableState.awaitDrain);
        src._readableState.awaitDrain++;
        increasedAwaitDrain = true;
      }
      src.pause();
    }
  }

  // if the dest has an error, then stop piping into it.
  // however, don't suppress the throwing behavior for this.
  function onerror(er) {
    debug('onerror', er);
    unpipe();
    dest.removeListener('error', onerror);
    if (EElistenerCount(dest, 'error') === 0) dest.emit('error', er);
  }

  // Make sure our error handler is attached before userland ones.
  prependListener(dest, 'error', onerror);

  // Both close and finish should trigger unpipe, but only once.
  function onclose() {
    dest.removeListener('finish', onfinish);
    unpipe();
  }
  dest.once('close', onclose);
  function onfinish() {
    debug('onfinish');
    dest.removeListener('close', onclose);
    unpipe();
  }
  dest.once('finish', onfinish);

  function unpipe() {
    debug('unpipe');
    src.unpipe(dest);
  }

  // tell the dest that it's being piped to
  dest.emit('pipe', src);

  // start the flow if it hasn't been started already.
  if (!state.flowing) {
    debug('pipe resume');
    src.resume();
  }

  return dest;
};

function pipeOnDrain(src) {
  return function () {
    var state = src._readableState;
    debug('pipeOnDrain', state.awaitDrain);
    if (state.awaitDrain) state.awaitDrain--;
    if (state.awaitDrain === 0 && EElistenerCount(src, 'data')) {
      state.flowing = true;
      flow(src);
    }
  };
}

Readable.prototype.unpipe = function (dest) {
  var state = this._readableState;
  var unpipeInfo = { hasUnpiped: false };

  // if we're not piping anywhere, then do nothing.
  if (state.pipesCount === 0) return this;

  // just one destination.  most common case.
  if (state.pipesCount === 1) {
    // passed in one, but it's not the right one.
    if (dest && dest !== state.pipes) return this;

    if (!dest) dest = state.pipes;

    // got a match.
    state.pipes = null;
    state.pipesCount = 0;
    state.flowing = false;
    if (dest) dest.emit('unpipe', this, unpipeInfo);
    return this;
  }

  // slow case. multiple pipe destinations.

  if (!dest) {
    // remove all.
    var dests = state.pipes;
    var len = state.pipesCount;
    state.pipes = null;
    state.pipesCount = 0;
    state.flowing = false;

    for (var i = 0; i < len; i++) {
      dests[i].emit('unpipe', this, unpipeInfo);
    }return this;
  }

  // try to find the right one.
  var index = indexOf(state.pipes, dest);
  if (index === -1) return this;

  state.pipes.splice(index, 1);
  state.pipesCount -= 1;
  if (state.pipesCount === 1) state.pipes = state.pipes[0];

  dest.emit('unpipe', this, unpipeInfo);

  return this;
};

// set up data events if they are asked for
// Ensure readable listeners eventually get something
Readable.prototype.on = function (ev, fn) {
  var res = Stream.prototype.on.call(this, ev, fn);

  if (ev === 'data') {
    // Start flowing on next tick if stream isn't explicitly paused
    if (this._readableState.flowing !== false) this.resume();
  } else if (ev === 'readable') {
    var state = this._readableState;
    if (!state.endEmitted && !state.readableListening) {
      state.readableListening = state.needReadable = true;
      state.emittedReadable = false;
      if (!state.reading) {
        processNextTick(nReadingNextTick, this);
      } else if (state.length) {
        emitReadable(this);
      }
    }
  }

  return res;
};
Readable.prototype.addListener = Readable.prototype.on;

function nReadingNextTick(self) {
  debug('readable nexttick read 0');
  self.read(0);
}

// pause() and resume() are remnants of the legacy readable stream API
// If the user uses them, then switch into old mode.
Readable.prototype.resume = function () {
  var state = this._readableState;
  if (!state.flowing) {
    debug('resume');
    state.flowing = true;
    resume(this, state);
  }
  return this;
};

function resume(stream, state) {
  if (!state.resumeScheduled) {
    state.resumeScheduled = true;
    processNextTick(resume_, stream, state);
  }
}

function resume_(stream, state) {
  if (!state.reading) {
    debug('resume read 0');
    stream.read(0);
  }

  state.resumeScheduled = false;
  state.awaitDrain = 0;
  stream.emit('resume');
  flow(stream);
  if (state.flowing && !state.reading) stream.read(0);
}

Readable.prototype.pause = function () {
  debug('call pause flowing=%j', this._readableState.flowing);
  if (false !== this._readableState.flowing) {
    debug('pause');
    this._readableState.flowing = false;
    this.emit('pause');
  }
  return this;
};

function flow(stream) {
  var state = stream._readableState;
  debug('flow', state.flowing);
  while (state.flowing && stream.read() !== null) {}
}

// wrap an old-style stream as the async data source.
// This is *not* part of the readable stream interface.
// It is an ugly unfortunate mess of history.
Readable.prototype.wrap = function (stream) {
  var state = this._readableState;
  var paused = false;

  var self = this;
  stream.on('end', function () {
    debug('wrapped end');
    if (state.decoder && !state.ended) {
      var chunk = state.decoder.end();
      if (chunk && chunk.length) self.push(chunk);
    }

    self.push(null);
  });

  stream.on('data', function (chunk) {
    debug('wrapped data');
    if (state.decoder) chunk = state.decoder.write(chunk);

    // don't skip over falsy values in objectMode
    if (state.objectMode && (chunk === null || chunk === undefined)) return;else if (!state.objectMode && (!chunk || !chunk.length)) return;

    var ret = self.push(chunk);
    if (!ret) {
      paused = true;
      stream.pause();
    }
  });

  // proxy all the other methods.
  // important when wrapping filters and duplexes.
  for (var i in stream) {
    if (this[i] === undefined && typeof stream[i] === 'function') {
      this[i] = function (method) {
        return function () {
          return stream[method].apply(stream, arguments);
        };
      }(i);
    }
  }

  // proxy certain important events.
  for (var n = 0; n < kProxyEvents.length; n++) {
    stream.on(kProxyEvents[n], self.emit.bind(self, kProxyEvents[n]));
  }

  // when we try to consume some more bytes, simply unpause the
  // underlying stream.
  self._read = function (n) {
    debug('wrapped _read', n);
    if (paused) {
      paused = false;
      stream.resume();
    }
  };

  return self;
};

// exposed for testing purposes only.
Readable._fromList = fromList;

// Pluck off n bytes from an array of buffers.
// Length is the combined lengths of all the buffers in the list.
// This function is designed to be inlinable, so please take care when making
// changes to the function body.
function fromList(n, state) {
  // nothing buffered
  if (state.length === 0) return null;

  var ret;
  if (state.objectMode) ret = state.buffer.shift();else if (!n || n >= state.length) {
    // read it all, truncate the list
    if (state.decoder) ret = state.buffer.join('');else if (state.buffer.length === 1) ret = state.buffer.head.data;else ret = state.buffer.concat(state.length);
    state.buffer.clear();
  } else {
    // read part of list
    ret = fromListPartial(n, state.buffer, state.decoder);
  }

  return ret;
}

// Extracts only enough buffered data to satisfy the amount requested.
// This function is designed to be inlinable, so please take care when making
// changes to the function body.
function fromListPartial(n, list, hasStrings) {
  var ret;
  if (n < list.head.data.length) {
    // slice is the same for buffers and strings
    ret = list.head.data.slice(0, n);
    list.head.data = list.head.data.slice(n);
  } else if (n === list.head.data.length) {
    // first chunk is a perfect match
    ret = list.shift();
  } else {
    // result spans more than one buffer
    ret = hasStrings ? copyFromBufferString(n, list) : copyFromBuffer(n, list);
  }
  return ret;
}

// Copies a specified amount of characters from the list of buffered data
// chunks.
// This function is designed to be inlinable, so please take care when making
// changes to the function body.
function copyFromBufferString(n, list) {
  var p = list.head;
  var c = 1;
  var ret = p.data;
  n -= ret.length;
  while (p = p.next) {
    var str = p.data;
    var nb = n > str.length ? str.length : n;
    if (nb === str.length) ret += str;else ret += str.slice(0, n);
    n -= nb;
    if (n === 0) {
      if (nb === str.length) {
        ++c;
        if (p.next) list.head = p.next;else list.head = list.tail = null;
      } else {
        list.head = p;
        p.data = str.slice(nb);
      }
      break;
    }
    ++c;
  }
  list.length -= c;
  return ret;
}

// Copies a specified amount of bytes from the list of buffered data chunks.
// This function is designed to be inlinable, so please take care when making
// changes to the function body.
function copyFromBuffer(n, list) {
  var ret = Buffer.allocUnsafe(n);
  var p = list.head;
  var c = 1;
  p.data.copy(ret);
  n -= p.data.length;
  while (p = p.next) {
    var buf = p.data;
    var nb = n > buf.length ? buf.length : n;
    buf.copy(ret, ret.length - n, 0, nb);
    n -= nb;
    if (n === 0) {
      if (nb === buf.length) {
        ++c;
        if (p.next) list.head = p.next;else list.head = list.tail = null;
      } else {
        list.head = p;
        p.data = buf.slice(nb);
      }
      break;
    }
    ++c;
  }
  list.length -= c;
  return ret;
}

function endReadable(stream) {
  var state = stream._readableState;

  // If we get here before consuming all the bytes, then that is a
  // bug in node.  Should never happen.
  if (state.length > 0) throw new Error('"endReadable()" called on non-empty stream');

  if (!state.endEmitted) {
    state.ended = true;
    processNextTick(endReadableNT, state, stream);
  }
}

function endReadableNT(state, stream) {
  // Check that we didn't get one last unshift.
  if (!state.endEmitted && state.length === 0) {
    state.endEmitted = true;
    stream.readable = false;
    stream.emit('end');
  }
}

function forEach(xs, f) {
  for (var i = 0, l = xs.length; i < l; i++) {
    f(xs[i], i);
  }
}

function indexOf(xs, x) {
  for (var i = 0, l = xs.length; i < l; i++) {
    if (xs[i] === x) return i;
  }
  return -1;
}
}).call(this,require('_process'),typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./_stream_duplex":31,"./internal/streams/BufferList":36,"./internal/streams/destroy":37,"./internal/streams/stream":38,"_process":18,"core-util-is":14,"events":17,"inherits":20,"isarray":22,"process-nextick-args":29,"safe-buffer":40,"string_decoder/":41,"util":11}],34:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

// a transform stream is a readable/writable stream where you do
// something with the data.  Sometimes it's called a "filter",
// but that's not a great name for it, since that implies a thing where
// some bits pass through, and others are simply ignored.  (That would
// be a valid example of a transform, of course.)
//
// While the output is causally related to the input, it's not a
// necessarily symmetric or synchronous transformation.  For example,
// a zlib stream might take multiple plain-text writes(), and then
// emit a single compressed chunk some time in the future.
//
// Here's how this works:
//
// The Transform stream has all the aspects of the readable and writable
// stream classes.  When you write(chunk), that calls _write(chunk,cb)
// internally, and returns false if there's a lot of pending writes
// buffered up.  When you call read(), that calls _read(n) until
// there's enough pending readable data buffered up.
//
// In a transform stream, the written data is placed in a buffer.  When
// _read(n) is called, it transforms the queued up data, calling the
// buffered _write cb's as it consumes chunks.  If consuming a single
// written chunk would result in multiple output chunks, then the first
// outputted bit calls the readcb, and subsequent chunks just go into
// the read buffer, and will cause it to emit 'readable' if necessary.
//
// This way, back-pressure is actually determined by the reading side,
// since _read has to be called to start processing a new chunk.  However,
// a pathological inflate type of transform can cause excessive buffering
// here.  For example, imagine a stream where every byte of input is
// interpreted as an integer from 0-255, and then results in that many
// bytes of output.  Writing the 4 bytes {ff,ff,ff,ff} would result in
// 1kb of data being output.  In this case, you could write a very small
// amount of input, and end up with a very large amount of output.  In
// such a pathological inflating mechanism, there'd be no way to tell
// the system to stop doing the transform.  A single 4MB write could
// cause the system to run out of memory.
//
// However, even in such a pathological case, only a single written chunk
// would be consumed, and then the rest would wait (un-transformed) until
// the results of the previous transformed chunk were consumed.

'use strict';

module.exports = Transform;

var Duplex = require('./_stream_duplex');

/*<replacement>*/
var util = require('core-util-is');
util.inherits = require('inherits');
/*</replacement>*/

util.inherits(Transform, Duplex);

function TransformState(stream) {
  this.afterTransform = function (er, data) {
    return afterTransform(stream, er, data);
  };

  this.needTransform = false;
  this.transforming = false;
  this.writecb = null;
  this.writechunk = null;
  this.writeencoding = null;
}

function afterTransform(stream, er, data) {
  var ts = stream._transformState;
  ts.transforming = false;

  var cb = ts.writecb;

  if (!cb) {
    return stream.emit('error', new Error('write callback called multiple times'));
  }

  ts.writechunk = null;
  ts.writecb = null;

  if (data !== null && data !== undefined) stream.push(data);

  cb(er);

  var rs = stream._readableState;
  rs.reading = false;
  if (rs.needReadable || rs.length < rs.highWaterMark) {
    stream._read(rs.highWaterMark);
  }
}

function Transform(options) {
  if (!(this instanceof Transform)) return new Transform(options);

  Duplex.call(this, options);

  this._transformState = new TransformState(this);

  var stream = this;

  // start out asking for a readable event once data is transformed.
  this._readableState.needReadable = true;

  // we have implemented the _read method, and done the other things
  // that Readable wants before the first _read call, so unset the
  // sync guard flag.
  this._readableState.sync = false;

  if (options) {
    if (typeof options.transform === 'function') this._transform = options.transform;

    if (typeof options.flush === 'function') this._flush = options.flush;
  }

  // When the writable side finishes, then flush out anything remaining.
  this.once('prefinish', function () {
    if (typeof this._flush === 'function') this._flush(function (er, data) {
      done(stream, er, data);
    });else done(stream);
  });
}

Transform.prototype.push = function (chunk, encoding) {
  this._transformState.needTransform = false;
  return Duplex.prototype.push.call(this, chunk, encoding);
};

// This is the part where you do stuff!
// override this function in implementation classes.
// 'chunk' is an input chunk.
//
// Call `push(newChunk)` to pass along transformed output
// to the readable side.  You may call 'push' zero or more times.
//
// Call `cb(err)` when you are done with this chunk.  If you pass
// an error, then that'll put the hurt on the whole operation.  If you
// never call cb(), then you'll never get another chunk.
Transform.prototype._transform = function (chunk, encoding, cb) {
  throw new Error('_transform() is not implemented');
};

Transform.prototype._write = function (chunk, encoding, cb) {
  var ts = this._transformState;
  ts.writecb = cb;
  ts.writechunk = chunk;
  ts.writeencoding = encoding;
  if (!ts.transforming) {
    var rs = this._readableState;
    if (ts.needTransform || rs.needReadable || rs.length < rs.highWaterMark) this._read(rs.highWaterMark);
  }
};

// Doesn't matter what the args are here.
// _transform does all the work.
// That we got here means that the readable side wants more data.
Transform.prototype._read = function (n) {
  var ts = this._transformState;

  if (ts.writechunk !== null && ts.writecb && !ts.transforming) {
    ts.transforming = true;
    this._transform(ts.writechunk, ts.writeencoding, ts.afterTransform);
  } else {
    // mark that we need a transform, so that any data that comes in
    // will get processed, now that we've asked for it.
    ts.needTransform = true;
  }
};

Transform.prototype._destroy = function (err, cb) {
  var _this = this;

  Duplex.prototype._destroy.call(this, err, function (err2) {
    cb(err2);
    _this.emit('close');
  });
};

function done(stream, er, data) {
  if (er) return stream.emit('error', er);

  if (data !== null && data !== undefined) stream.push(data);

  // if there's nothing in the write buffer, then that means
  // that nothing more will ever be provided
  var ws = stream._writableState;
  var ts = stream._transformState;

  if (ws.length) throw new Error('Calling transform done when ws.length != 0');

  if (ts.transforming) throw new Error('Calling transform done when still transforming');

  return stream.push(null);
}
},{"./_stream_duplex":31,"core-util-is":14,"inherits":20}],35:[function(require,module,exports){
(function (process,global){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

// A bit simpler than readable streams.
// Implement an async ._write(chunk, encoding, cb), and it'll handle all
// the drain event emission and buffering.

'use strict';

/*<replacement>*/

var processNextTick = require('process-nextick-args');
/*</replacement>*/

module.exports = Writable;

/* <replacement> */
function WriteReq(chunk, encoding, cb) {
  this.chunk = chunk;
  this.encoding = encoding;
  this.callback = cb;
  this.next = null;
}

// It seems a linked list but it is not
// there will be only 2 of these for each stream
function CorkedRequest(state) {
  var _this = this;

  this.next = null;
  this.entry = null;
  this.finish = function () {
    onCorkedFinish(_this, state);
  };
}
/* </replacement> */

/*<replacement>*/
var asyncWrite = !process.browser && ['v0.10', 'v0.9.'].indexOf(process.version.slice(0, 5)) > -1 ? setImmediate : processNextTick;
/*</replacement>*/

/*<replacement>*/
var Duplex;
/*</replacement>*/

Writable.WritableState = WritableState;

/*<replacement>*/
var util = require('core-util-is');
util.inherits = require('inherits');
/*</replacement>*/

/*<replacement>*/
var internalUtil = {
  deprecate: require('util-deprecate')
};
/*</replacement>*/

/*<replacement>*/
var Stream = require('./internal/streams/stream');
/*</replacement>*/

/*<replacement>*/
var Buffer = require('safe-buffer').Buffer;
var OurUint8Array = global.Uint8Array || function () {};
function _uint8ArrayToBuffer(chunk) {
  return Buffer.from(chunk);
}
function _isUint8Array(obj) {
  return Buffer.isBuffer(obj) || obj instanceof OurUint8Array;
}
/*</replacement>*/

var destroyImpl = require('./internal/streams/destroy');

util.inherits(Writable, Stream);

function nop() {}

function WritableState(options, stream) {
  Duplex = Duplex || require('./_stream_duplex');

  options = options || {};

  // object stream flag to indicate whether or not this stream
  // contains buffers or objects.
  this.objectMode = !!options.objectMode;

  if (stream instanceof Duplex) this.objectMode = this.objectMode || !!options.writableObjectMode;

  // the point at which write() starts returning false
  // Note: 0 is a valid value, means that we always return false if
  // the entire buffer is not flushed immediately on write()
  var hwm = options.highWaterMark;
  var defaultHwm = this.objectMode ? 16 : 16 * 1024;
  this.highWaterMark = hwm || hwm === 0 ? hwm : defaultHwm;

  // cast to ints.
  this.highWaterMark = Math.floor(this.highWaterMark);

  // if _final has been called
  this.finalCalled = false;

  // drain event flag.
  this.needDrain = false;
  // at the start of calling end()
  this.ending = false;
  // when end() has been called, and returned
  this.ended = false;
  // when 'finish' is emitted
  this.finished = false;

  // has it been destroyed
  this.destroyed = false;

  // should we decode strings into buffers before passing to _write?
  // this is here so that some node-core streams can optimize string
  // handling at a lower level.
  var noDecode = options.decodeStrings === false;
  this.decodeStrings = !noDecode;

  // Crypto is kind of old and crusty.  Historically, its default string
  // encoding is 'binary' so we have to make this configurable.
  // Everything else in the universe uses 'utf8', though.
  this.defaultEncoding = options.defaultEncoding || 'utf8';

  // not an actual buffer we keep track of, but a measurement
  // of how much we're waiting to get pushed to some underlying
  // socket or file.
  this.length = 0;

  // a flag to see when we're in the middle of a write.
  this.writing = false;

  // when true all writes will be buffered until .uncork() call
  this.corked = 0;

  // a flag to be able to tell if the onwrite cb is called immediately,
  // or on a later tick.  We set this to true at first, because any
  // actions that shouldn't happen until "later" should generally also
  // not happen before the first write call.
  this.sync = true;

  // a flag to know if we're processing previously buffered items, which
  // may call the _write() callback in the same tick, so that we don't
  // end up in an overlapped onwrite situation.
  this.bufferProcessing = false;

  // the callback that's passed to _write(chunk,cb)
  this.onwrite = function (er) {
    onwrite(stream, er);
  };

  // the callback that the user supplies to write(chunk,encoding,cb)
  this.writecb = null;

  // the amount that is being written when _write is called.
  this.writelen = 0;

  this.bufferedRequest = null;
  this.lastBufferedRequest = null;

  // number of pending user-supplied write callbacks
  // this must be 0 before 'finish' can be emitted
  this.pendingcb = 0;

  // emit prefinish if the only thing we're waiting for is _write cbs
  // This is relevant for synchronous Transform streams
  this.prefinished = false;

  // True if the error was already emitted and should not be thrown again
  this.errorEmitted = false;

  // count buffered requests
  this.bufferedRequestCount = 0;

  // allocate the first CorkedRequest, there is always
  // one allocated and free to use, and we maintain at most two
  this.corkedRequestsFree = new CorkedRequest(this);
}

WritableState.prototype.getBuffer = function getBuffer() {
  var current = this.bufferedRequest;
  var out = [];
  while (current) {
    out.push(current);
    current = current.next;
  }
  return out;
};

(function () {
  try {
    Object.defineProperty(WritableState.prototype, 'buffer', {
      get: internalUtil.deprecate(function () {
        return this.getBuffer();
      }, '_writableState.buffer is deprecated. Use _writableState.getBuffer ' + 'instead.', 'DEP0003')
    });
  } catch (_) {}
})();

// Test _writableState for inheritance to account for Duplex streams,
// whose prototype chain only points to Readable.
var realHasInstance;
if (typeof Symbol === 'function' && Symbol.hasInstance && typeof Function.prototype[Symbol.hasInstance] === 'function') {
  realHasInstance = Function.prototype[Symbol.hasInstance];
  Object.defineProperty(Writable, Symbol.hasInstance, {
    value: function (object) {
      if (realHasInstance.call(this, object)) return true;

      return object && object._writableState instanceof WritableState;
    }
  });
} else {
  realHasInstance = function (object) {
    return object instanceof this;
  };
}

function Writable(options) {
  Duplex = Duplex || require('./_stream_duplex');

  // Writable ctor is applied to Duplexes, too.
  // `realHasInstance` is necessary because using plain `instanceof`
  // would return false, as no `_writableState` property is attached.

  // Trying to use the custom `instanceof` for Writable here will also break the
  // Node.js LazyTransform implementation, which has a non-trivial getter for
  // `_writableState` that would lead to infinite recursion.
  if (!realHasInstance.call(Writable, this) && !(this instanceof Duplex)) {
    return new Writable(options);
  }

  this._writableState = new WritableState(options, this);

  // legacy.
  this.writable = true;

  if (options) {
    if (typeof options.write === 'function') this._write = options.write;

    if (typeof options.writev === 'function') this._writev = options.writev;

    if (typeof options.destroy === 'function') this._destroy = options.destroy;

    if (typeof options.final === 'function') this._final = options.final;
  }

  Stream.call(this);
}

// Otherwise people can pipe Writable streams, which is just wrong.
Writable.prototype.pipe = function () {
  this.emit('error', new Error('Cannot pipe, not readable'));
};

function writeAfterEnd(stream, cb) {
  var er = new Error('write after end');
  // TODO: defer error events consistently everywhere, not just the cb
  stream.emit('error', er);
  processNextTick(cb, er);
}

// Checks that a user-supplied chunk is valid, especially for the particular
// mode the stream is in. Currently this means that `null` is never accepted
// and undefined/non-string values are only allowed in object mode.
function validChunk(stream, state, chunk, cb) {
  var valid = true;
  var er = false;

  if (chunk === null) {
    er = new TypeError('May not write null values to stream');
  } else if (typeof chunk !== 'string' && chunk !== undefined && !state.objectMode) {
    er = new TypeError('Invalid non-string/buffer chunk');
  }
  if (er) {
    stream.emit('error', er);
    processNextTick(cb, er);
    valid = false;
  }
  return valid;
}

Writable.prototype.write = function (chunk, encoding, cb) {
  var state = this._writableState;
  var ret = false;
  var isBuf = _isUint8Array(chunk) && !state.objectMode;

  if (isBuf && !Buffer.isBuffer(chunk)) {
    chunk = _uint8ArrayToBuffer(chunk);
  }

  if (typeof encoding === 'function') {
    cb = encoding;
    encoding = null;
  }

  if (isBuf) encoding = 'buffer';else if (!encoding) encoding = state.defaultEncoding;

  if (typeof cb !== 'function') cb = nop;

  if (state.ended) writeAfterEnd(this, cb);else if (isBuf || validChunk(this, state, chunk, cb)) {
    state.pendingcb++;
    ret = writeOrBuffer(this, state, isBuf, chunk, encoding, cb);
  }

  return ret;
};

Writable.prototype.cork = function () {
  var state = this._writableState;

  state.corked++;
};

Writable.prototype.uncork = function () {
  var state = this._writableState;

  if (state.corked) {
    state.corked--;

    if (!state.writing && !state.corked && !state.finished && !state.bufferProcessing && state.bufferedRequest) clearBuffer(this, state);
  }
};

Writable.prototype.setDefaultEncoding = function setDefaultEncoding(encoding) {
  // node::ParseEncoding() requires lower case.
  if (typeof encoding === 'string') encoding = encoding.toLowerCase();
  if (!(['hex', 'utf8', 'utf-8', 'ascii', 'binary', 'base64', 'ucs2', 'ucs-2', 'utf16le', 'utf-16le', 'raw'].indexOf((encoding + '').toLowerCase()) > -1)) throw new TypeError('Unknown encoding: ' + encoding);
  this._writableState.defaultEncoding = encoding;
  return this;
};

function decodeChunk(state, chunk, encoding) {
  if (!state.objectMode && state.decodeStrings !== false && typeof chunk === 'string') {
    chunk = Buffer.from(chunk, encoding);
  }
  return chunk;
}

// if we're already writing something, then just put this
// in the queue, and wait our turn.  Otherwise, call _write
// If we return false, then we need a drain event, so set that flag.
function writeOrBuffer(stream, state, isBuf, chunk, encoding, cb) {
  if (!isBuf) {
    var newChunk = decodeChunk(state, chunk, encoding);
    if (chunk !== newChunk) {
      isBuf = true;
      encoding = 'buffer';
      chunk = newChunk;
    }
  }
  var len = state.objectMode ? 1 : chunk.length;

  state.length += len;

  var ret = state.length < state.highWaterMark;
  // we must ensure that previous needDrain will not be reset to false.
  if (!ret) state.needDrain = true;

  if (state.writing || state.corked) {
    var last = state.lastBufferedRequest;
    state.lastBufferedRequest = {
      chunk: chunk,
      encoding: encoding,
      isBuf: isBuf,
      callback: cb,
      next: null
    };
    if (last) {
      last.next = state.lastBufferedRequest;
    } else {
      state.bufferedRequest = state.lastBufferedRequest;
    }
    state.bufferedRequestCount += 1;
  } else {
    doWrite(stream, state, false, len, chunk, encoding, cb);
  }

  return ret;
}

function doWrite(stream, state, writev, len, chunk, encoding, cb) {
  state.writelen = len;
  state.writecb = cb;
  state.writing = true;
  state.sync = true;
  if (writev) stream._writev(chunk, state.onwrite);else stream._write(chunk, encoding, state.onwrite);
  state.sync = false;
}

function onwriteError(stream, state, sync, er, cb) {
  --state.pendingcb;

  if (sync) {
    // defer the callback if we are being called synchronously
    // to avoid piling up things on the stack
    processNextTick(cb, er);
    // this can emit finish, and it will always happen
    // after error
    processNextTick(finishMaybe, stream, state);
    stream._writableState.errorEmitted = true;
    stream.emit('error', er);
  } else {
    // the caller expect this to happen before if
    // it is async
    cb(er);
    stream._writableState.errorEmitted = true;
    stream.emit('error', er);
    // this can emit finish, but finish must
    // always follow error
    finishMaybe(stream, state);
  }
}

function onwriteStateUpdate(state) {
  state.writing = false;
  state.writecb = null;
  state.length -= state.writelen;
  state.writelen = 0;
}

function onwrite(stream, er) {
  var state = stream._writableState;
  var sync = state.sync;
  var cb = state.writecb;

  onwriteStateUpdate(state);

  if (er) onwriteError(stream, state, sync, er, cb);else {
    // Check if we're actually ready to finish, but don't emit yet
    var finished = needFinish(state);

    if (!finished && !state.corked && !state.bufferProcessing && state.bufferedRequest) {
      clearBuffer(stream, state);
    }

    if (sync) {
      /*<replacement>*/
      asyncWrite(afterWrite, stream, state, finished, cb);
      /*</replacement>*/
    } else {
      afterWrite(stream, state, finished, cb);
    }
  }
}

function afterWrite(stream, state, finished, cb) {
  if (!finished) onwriteDrain(stream, state);
  state.pendingcb--;
  cb();
  finishMaybe(stream, state);
}

// Must force callback to be called on nextTick, so that we don't
// emit 'drain' before the write() consumer gets the 'false' return
// value, and has a chance to attach a 'drain' listener.
function onwriteDrain(stream, state) {
  if (state.length === 0 && state.needDrain) {
    state.needDrain = false;
    stream.emit('drain');
  }
}

// if there's something in the buffer waiting, then process it
function clearBuffer(stream, state) {
  state.bufferProcessing = true;
  var entry = state.bufferedRequest;

  if (stream._writev && entry && entry.next) {
    // Fast case, write everything using _writev()
    var l = state.bufferedRequestCount;
    var buffer = new Array(l);
    var holder = state.corkedRequestsFree;
    holder.entry = entry;

    var count = 0;
    var allBuffers = true;
    while (entry) {
      buffer[count] = entry;
      if (!entry.isBuf) allBuffers = false;
      entry = entry.next;
      count += 1;
    }
    buffer.allBuffers = allBuffers;

    doWrite(stream, state, true, state.length, buffer, '', holder.finish);

    // doWrite is almost always async, defer these to save a bit of time
    // as the hot path ends with doWrite
    state.pendingcb++;
    state.lastBufferedRequest = null;
    if (holder.next) {
      state.corkedRequestsFree = holder.next;
      holder.next = null;
    } else {
      state.corkedRequestsFree = new CorkedRequest(state);
    }
  } else {
    // Slow case, write chunks one-by-one
    while (entry) {
      var chunk = entry.chunk;
      var encoding = entry.encoding;
      var cb = entry.callback;
      var len = state.objectMode ? 1 : chunk.length;

      doWrite(stream, state, false, len, chunk, encoding, cb);
      entry = entry.next;
      // if we didn't call the onwrite immediately, then
      // it means that we need to wait until it does.
      // also, that means that the chunk and cb are currently
      // being processed, so move the buffer counter past them.
      if (state.writing) {
        break;
      }
    }

    if (entry === null) state.lastBufferedRequest = null;
  }

  state.bufferedRequestCount = 0;
  state.bufferedRequest = entry;
  state.bufferProcessing = false;
}

Writable.prototype._write = function (chunk, encoding, cb) {
  cb(new Error('_write() is not implemented'));
};

Writable.prototype._writev = null;

Writable.prototype.end = function (chunk, encoding, cb) {
  var state = this._writableState;

  if (typeof chunk === 'function') {
    cb = chunk;
    chunk = null;
    encoding = null;
  } else if (typeof encoding === 'function') {
    cb = encoding;
    encoding = null;
  }

  if (chunk !== null && chunk !== undefined) this.write(chunk, encoding);

  // .end() fully uncorks
  if (state.corked) {
    state.corked = 1;
    this.uncork();
  }

  // ignore unnecessary end() calls.
  if (!state.ending && !state.finished) endWritable(this, state, cb);
};

function needFinish(state) {
  return state.ending && state.length === 0 && state.bufferedRequest === null && !state.finished && !state.writing;
}
function callFinal(stream, state) {
  stream._final(function (err) {
    state.pendingcb--;
    if (err) {
      stream.emit('error', err);
    }
    state.prefinished = true;
    stream.emit('prefinish');
    finishMaybe(stream, state);
  });
}
function prefinish(stream, state) {
  if (!state.prefinished && !state.finalCalled) {
    if (typeof stream._final === 'function') {
      state.pendingcb++;
      state.finalCalled = true;
      processNextTick(callFinal, stream, state);
    } else {
      state.prefinished = true;
      stream.emit('prefinish');
    }
  }
}

function finishMaybe(stream, state) {
  var need = needFinish(state);
  if (need) {
    prefinish(stream, state);
    if (state.pendingcb === 0) {
      state.finished = true;
      stream.emit('finish');
    }
  }
  return need;
}

function endWritable(stream, state, cb) {
  state.ending = true;
  finishMaybe(stream, state);
  if (cb) {
    if (state.finished) processNextTick(cb);else stream.once('finish', cb);
  }
  state.ended = true;
  stream.writable = false;
}

function onCorkedFinish(corkReq, state, err) {
  var entry = corkReq.entry;
  corkReq.entry = null;
  while (entry) {
    var cb = entry.callback;
    state.pendingcb--;
    cb(err);
    entry = entry.next;
  }
  if (state.corkedRequestsFree) {
    state.corkedRequestsFree.next = corkReq;
  } else {
    state.corkedRequestsFree = corkReq;
  }
}

Object.defineProperty(Writable.prototype, 'destroyed', {
  get: function () {
    if (this._writableState === undefined) {
      return false;
    }
    return this._writableState.destroyed;
  },
  set: function (value) {
    // we ignore the value if the stream
    // has not been initialized yet
    if (!this._writableState) {
      return;
    }

    // backward compatibility, the user is explicitly
    // managing destroyed
    this._writableState.destroyed = value;
  }
});

Writable.prototype.destroy = destroyImpl.destroy;
Writable.prototype._undestroy = destroyImpl.undestroy;
Writable.prototype._destroy = function (err, cb) {
  this.end();
  cb(err);
};
}).call(this,require('_process'),typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./_stream_duplex":31,"./internal/streams/destroy":37,"./internal/streams/stream":38,"_process":18,"core-util-is":14,"inherits":20,"process-nextick-args":29,"safe-buffer":40,"util-deprecate":42}],36:[function(require,module,exports){
'use strict';

/*<replacement>*/

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var Buffer = require('safe-buffer').Buffer;
/*</replacement>*/

function copyBuffer(src, target, offset) {
  src.copy(target, offset);
}

module.exports = function () {
  function BufferList() {
    _classCallCheck(this, BufferList);

    this.head = null;
    this.tail = null;
    this.length = 0;
  }

  BufferList.prototype.push = function push(v) {
    var entry = { data: v, next: null };
    if (this.length > 0) this.tail.next = entry;else this.head = entry;
    this.tail = entry;
    ++this.length;
  };

  BufferList.prototype.unshift = function unshift(v) {
    var entry = { data: v, next: this.head };
    if (this.length === 0) this.tail = entry;
    this.head = entry;
    ++this.length;
  };

  BufferList.prototype.shift = function shift() {
    if (this.length === 0) return;
    var ret = this.head.data;
    if (this.length === 1) this.head = this.tail = null;else this.head = this.head.next;
    --this.length;
    return ret;
  };

  BufferList.prototype.clear = function clear() {
    this.head = this.tail = null;
    this.length = 0;
  };

  BufferList.prototype.join = function join(s) {
    if (this.length === 0) return '';
    var p = this.head;
    var ret = '' + p.data;
    while (p = p.next) {
      ret += s + p.data;
    }return ret;
  };

  BufferList.prototype.concat = function concat(n) {
    if (this.length === 0) return Buffer.alloc(0);
    if (this.length === 1) return this.head.data;
    var ret = Buffer.allocUnsafe(n >>> 0);
    var p = this.head;
    var i = 0;
    while (p) {
      copyBuffer(p.data, ret, i);
      i += p.data.length;
      p = p.next;
    }
    return ret;
  };

  return BufferList;
}();
},{"safe-buffer":40}],37:[function(require,module,exports){
'use strict';

/*<replacement>*/

var processNextTick = require('process-nextick-args');
/*</replacement>*/

// undocumented cb() API, needed for core, not for public API
function destroy(err, cb) {
  var _this = this;

  var readableDestroyed = this._readableState && this._readableState.destroyed;
  var writableDestroyed = this._writableState && this._writableState.destroyed;

  if (readableDestroyed || writableDestroyed) {
    if (cb) {
      cb(err);
    } else if (err && (!this._writableState || !this._writableState.errorEmitted)) {
      processNextTick(emitErrorNT, this, err);
    }
    return;
  }

  // we set destroyed to true before firing error callbacks in order
  // to make it re-entrance safe in case destroy() is called within callbacks

  if (this._readableState) {
    this._readableState.destroyed = true;
  }

  // if this is a duplex stream mark the writable part as destroyed as well
  if (this._writableState) {
    this._writableState.destroyed = true;
  }

  this._destroy(err || null, function (err) {
    if (!cb && err) {
      processNextTick(emitErrorNT, _this, err);
      if (_this._writableState) {
        _this._writableState.errorEmitted = true;
      }
    } else if (cb) {
      cb(err);
    }
  });
}

function undestroy() {
  if (this._readableState) {
    this._readableState.destroyed = false;
    this._readableState.reading = false;
    this._readableState.ended = false;
    this._readableState.endEmitted = false;
  }

  if (this._writableState) {
    this._writableState.destroyed = false;
    this._writableState.ended = false;
    this._writableState.ending = false;
    this._writableState.finished = false;
    this._writableState.errorEmitted = false;
  }
}

function emitErrorNT(self, err) {
  self.emit('error', err);
}

module.exports = {
  destroy: destroy,
  undestroy: undestroy
};
},{"process-nextick-args":29}],38:[function(require,module,exports){
module.exports = require('events').EventEmitter;

},{"events":17}],39:[function(require,module,exports){
exports = module.exports = require('./lib/_stream_readable.js');
exports.Stream = exports;
exports.Readable = exports;
exports.Writable = require('./lib/_stream_writable.js');
exports.Duplex = require('./lib/_stream_duplex.js');
exports.Transform = require('./lib/_stream_transform.js');
exports.PassThrough = require('./lib/_stream_passthrough.js');

},{"./lib/_stream_duplex.js":31,"./lib/_stream_passthrough.js":32,"./lib/_stream_readable.js":33,"./lib/_stream_transform.js":34,"./lib/_stream_writable.js":35}],40:[function(require,module,exports){
/* eslint-disable node/no-deprecated-api */
var buffer = require('buffer')
var Buffer = buffer.Buffer

// alternative to using Object.keys for old browsers
function copyProps (src, dst) {
  for (var key in src) {
    dst[key] = src[key]
  }
}
if (Buffer.from && Buffer.alloc && Buffer.allocUnsafe && Buffer.allocUnsafeSlow) {
  module.exports = buffer
} else {
  // Copy properties from require('buffer')
  copyProps(buffer, exports)
  exports.Buffer = SafeBuffer
}

function SafeBuffer (arg, encodingOrOffset, length) {
  return Buffer(arg, encodingOrOffset, length)
}

// Copy static methods from Buffer
copyProps(Buffer, SafeBuffer)

SafeBuffer.from = function (arg, encodingOrOffset, length) {
  if (typeof arg === 'number') {
    throw new TypeError('Argument must not be a number')
  }
  return Buffer(arg, encodingOrOffset, length)
}

SafeBuffer.alloc = function (size, fill, encoding) {
  if (typeof size !== 'number') {
    throw new TypeError('Argument must be a number')
  }
  var buf = Buffer(size)
  if (fill !== undefined) {
    if (typeof encoding === 'string') {
      buf.fill(fill, encoding)
    } else {
      buf.fill(fill)
    }
  } else {
    buf.fill(0)
  }
  return buf
}

SafeBuffer.allocUnsafe = function (size) {
  if (typeof size !== 'number') {
    throw new TypeError('Argument must be a number')
  }
  return Buffer(size)
}

SafeBuffer.allocUnsafeSlow = function (size) {
  if (typeof size !== 'number') {
    throw new TypeError('Argument must be a number')
  }
  return buffer.SlowBuffer(size)
}

},{"buffer":12}],41:[function(require,module,exports){
'use strict';

var Buffer = require('safe-buffer').Buffer;

var isEncoding = Buffer.isEncoding || function (encoding) {
  encoding = '' + encoding;
  switch (encoding && encoding.toLowerCase()) {
    case 'hex':case 'utf8':case 'utf-8':case 'ascii':case 'binary':case 'base64':case 'ucs2':case 'ucs-2':case 'utf16le':case 'utf-16le':case 'raw':
      return true;
    default:
      return false;
  }
};

function _normalizeEncoding(enc) {
  if (!enc) return 'utf8';
  var retried;
  while (true) {
    switch (enc) {
      case 'utf8':
      case 'utf-8':
        return 'utf8';
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return 'utf16le';
      case 'latin1':
      case 'binary':
        return 'latin1';
      case 'base64':
      case 'ascii':
      case 'hex':
        return enc;
      default:
        if (retried) return; // undefined
        enc = ('' + enc).toLowerCase();
        retried = true;
    }
  }
};

// Do not cache `Buffer.isEncoding` when checking encoding names as some
// modules monkey-patch it to support additional encodings
function normalizeEncoding(enc) {
  var nenc = _normalizeEncoding(enc);
  if (typeof nenc !== 'string' && (Buffer.isEncoding === isEncoding || !isEncoding(enc))) throw new Error('Unknown encoding: ' + enc);
  return nenc || enc;
}

// StringDecoder provides an interface for efficiently splitting a series of
// buffers into a series of JS strings without breaking apart multi-byte
// characters.
exports.StringDecoder = StringDecoder;
function StringDecoder(encoding) {
  this.encoding = normalizeEncoding(encoding);
  var nb;
  switch (this.encoding) {
    case 'utf16le':
      this.text = utf16Text;
      this.end = utf16End;
      nb = 4;
      break;
    case 'utf8':
      this.fillLast = utf8FillLast;
      nb = 4;
      break;
    case 'base64':
      this.text = base64Text;
      this.end = base64End;
      nb = 3;
      break;
    default:
      this.write = simpleWrite;
      this.end = simpleEnd;
      return;
  }
  this.lastNeed = 0;
  this.lastTotal = 0;
  this.lastChar = Buffer.allocUnsafe(nb);
}

StringDecoder.prototype.write = function (buf) {
  if (buf.length === 0) return '';
  var r;
  var i;
  if (this.lastNeed) {
    r = this.fillLast(buf);
    if (r === undefined) return '';
    i = this.lastNeed;
    this.lastNeed = 0;
  } else {
    i = 0;
  }
  if (i < buf.length) return r ? r + this.text(buf, i) : this.text(buf, i);
  return r || '';
};

StringDecoder.prototype.end = utf8End;

// Returns only complete characters in a Buffer
StringDecoder.prototype.text = utf8Text;

// Attempts to complete a partial non-UTF-8 character using bytes from a Buffer
StringDecoder.prototype.fillLast = function (buf) {
  if (this.lastNeed <= buf.length) {
    buf.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, this.lastNeed);
    return this.lastChar.toString(this.encoding, 0, this.lastTotal);
  }
  buf.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, buf.length);
  this.lastNeed -= buf.length;
};

// Checks the type of a UTF-8 byte, whether it's ASCII, a leading byte, or a
// continuation byte.
function utf8CheckByte(byte) {
  if (byte <= 0x7F) return 0;else if (byte >> 5 === 0x06) return 2;else if (byte >> 4 === 0x0E) return 3;else if (byte >> 3 === 0x1E) return 4;
  return -1;
}

// Checks at most 3 bytes at the end of a Buffer in order to detect an
// incomplete multi-byte UTF-8 character. The total number of bytes (2, 3, or 4)
// needed to complete the UTF-8 character (if applicable) are returned.
function utf8CheckIncomplete(self, buf, i) {
  var j = buf.length - 1;
  if (j < i) return 0;
  var nb = utf8CheckByte(buf[j]);
  if (nb >= 0) {
    if (nb > 0) self.lastNeed = nb - 1;
    return nb;
  }
  if (--j < i) return 0;
  nb = utf8CheckByte(buf[j]);
  if (nb >= 0) {
    if (nb > 0) self.lastNeed = nb - 2;
    return nb;
  }
  if (--j < i) return 0;
  nb = utf8CheckByte(buf[j]);
  if (nb >= 0) {
    if (nb > 0) {
      if (nb === 2) nb = 0;else self.lastNeed = nb - 3;
    }
    return nb;
  }
  return 0;
}

// Validates as many continuation bytes for a multi-byte UTF-8 character as
// needed or are available. If we see a non-continuation byte where we expect
// one, we "replace" the validated continuation bytes we've seen so far with
// UTF-8 replacement characters ('\ufffd'), to match v8's UTF-8 decoding
// behavior. The continuation byte check is included three times in the case
// where all of the continuation bytes for a character exist in the same buffer.
// It is also done this way as a slight performance increase instead of using a
// loop.
function utf8CheckExtraBytes(self, buf, p) {
  if ((buf[0] & 0xC0) !== 0x80) {
    self.lastNeed = 0;
    return '\ufffd'.repeat(p);
  }
  if (self.lastNeed > 1 && buf.length > 1) {
    if ((buf[1] & 0xC0) !== 0x80) {
      self.lastNeed = 1;
      return '\ufffd'.repeat(p + 1);
    }
    if (self.lastNeed > 2 && buf.length > 2) {
      if ((buf[2] & 0xC0) !== 0x80) {
        self.lastNeed = 2;
        return '\ufffd'.repeat(p + 2);
      }
    }
  }
}

// Attempts to complete a multi-byte UTF-8 character using bytes from a Buffer.
function utf8FillLast(buf) {
  var p = this.lastTotal - this.lastNeed;
  var r = utf8CheckExtraBytes(this, buf, p);
  if (r !== undefined) return r;
  if (this.lastNeed <= buf.length) {
    buf.copy(this.lastChar, p, 0, this.lastNeed);
    return this.lastChar.toString(this.encoding, 0, this.lastTotal);
  }
  buf.copy(this.lastChar, p, 0, buf.length);
  this.lastNeed -= buf.length;
}

// Returns all complete UTF-8 characters in a Buffer. If the Buffer ended on a
// partial character, the character's bytes are buffered until the required
// number of bytes are available.
function utf8Text(buf, i) {
  var total = utf8CheckIncomplete(this, buf, i);
  if (!this.lastNeed) return buf.toString('utf8', i);
  this.lastTotal = total;
  var end = buf.length - (total - this.lastNeed);
  buf.copy(this.lastChar, 0, end);
  return buf.toString('utf8', i, end);
}

// For UTF-8, a replacement character for each buffered byte of a (partial)
// character needs to be added to the output.
function utf8End(buf) {
  var r = buf && buf.length ? this.write(buf) : '';
  if (this.lastNeed) return r + '\ufffd'.repeat(this.lastTotal - this.lastNeed);
  return r;
}

// UTF-16LE typically needs two bytes per character, but even if we have an even
// number of bytes available, we need to check if we end on a leading/high
// surrogate. In that case, we need to wait for the next two bytes in order to
// decode the last character properly.
function utf16Text(buf, i) {
  if ((buf.length - i) % 2 === 0) {
    var r = buf.toString('utf16le', i);
    if (r) {
      var c = r.charCodeAt(r.length - 1);
      if (c >= 0xD800 && c <= 0xDBFF) {
        this.lastNeed = 2;
        this.lastTotal = 4;
        this.lastChar[0] = buf[buf.length - 2];
        this.lastChar[1] = buf[buf.length - 1];
        return r.slice(0, -1);
      }
    }
    return r;
  }
  this.lastNeed = 1;
  this.lastTotal = 2;
  this.lastChar[0] = buf[buf.length - 1];
  return buf.toString('utf16le', i, buf.length - 1);
}

// For UTF-16LE we do not explicitly append special replacement characters if we
// end on a partial character, we simply let v8 handle that.
function utf16End(buf) {
  var r = buf && buf.length ? this.write(buf) : '';
  if (this.lastNeed) {
    var end = this.lastTotal - this.lastNeed;
    return r + this.lastChar.toString('utf16le', 0, end);
  }
  return r;
}

function base64Text(buf, i) {
  var n = (buf.length - i) % 3;
  if (n === 0) return buf.toString('base64', i);
  this.lastNeed = 3 - n;
  this.lastTotal = 3;
  if (n === 1) {
    this.lastChar[0] = buf[buf.length - 1];
  } else {
    this.lastChar[0] = buf[buf.length - 2];
    this.lastChar[1] = buf[buf.length - 1];
  }
  return buf.toString('base64', i, buf.length - n);
}

function base64End(buf) {
  var r = buf && buf.length ? this.write(buf) : '';
  if (this.lastNeed) return r + this.lastChar.toString('base64', 0, 3 - this.lastNeed);
  return r;
}

// Pass bytes on through for single-byte encodings (e.g. ascii, latin1, hex)
function simpleWrite(buf) {
  return buf.toString(this.encoding);
}

function simpleEnd(buf) {
  return buf && buf.length ? this.write(buf) : '';
}
},{"safe-buffer":40}],42:[function(require,module,exports){
(function (global){

/**
 * Module exports.
 */

module.exports = deprecate;

/**
 * Mark that a method should not be used.
 * Returns a modified function which warns once by default.
 *
 * If `localStorage.noDeprecation = true` is set, then it is a no-op.
 *
 * If `localStorage.throwDeprecation = true` is set, then deprecated functions
 * will throw an Error when invoked.
 *
 * If `localStorage.traceDeprecation = true` is set, then deprecated functions
 * will invoke `console.trace()` instead of `console.error()`.
 *
 * @param {Function} fn - the function to deprecate
 * @param {String} msg - the string to print to the console when `fn` is invoked
 * @returns {Function} a new "deprecated" version of `fn`
 * @api public
 */

function deprecate (fn, msg) {
  if (config('noDeprecation')) {
    return fn;
  }

  var warned = false;
  function deprecated() {
    if (!warned) {
      if (config('throwDeprecation')) {
        throw new Error(msg);
      } else if (config('traceDeprecation')) {
        console.trace(msg);
      } else {
        console.warn(msg);
      }
      warned = true;
    }
    return fn.apply(this, arguments);
  }

  return deprecated;
}

/**
 * Checks `localStorage` for boolean values for the given `name`.
 *
 * @param {String} name
 * @returns {Boolean}
 * @api private
 */

function config (name) {
  // accessing global.localStorage can trigger a DOMException in sandboxed iframes
  try {
    if (!global.localStorage) return false;
  } catch (_) {
    return false;
  }
  var val = global.localStorage[name];
  if (null == val) return false;
  return String(val).toLowerCase() === 'true';
}

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}],43:[function(require,module,exports){
arguments[4][20][0].apply(exports,arguments)
},{"dup":20}],44:[function(require,module,exports){
module.exports = function isBuffer(arg) {
  return arg && typeof arg === 'object'
    && typeof arg.copy === 'function'
    && typeof arg.fill === 'function'
    && typeof arg.readUInt8 === 'function';
}
},{}],45:[function(require,module,exports){
(function (process,global){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var formatRegExp = /%[sdj%]/g;
exports.format = function(f) {
  if (!isString(f)) {
    var objects = [];
    for (var i = 0; i < arguments.length; i++) {
      objects.push(inspect(arguments[i]));
    }
    return objects.join(' ');
  }

  var i = 1;
  var args = arguments;
  var len = args.length;
  var str = String(f).replace(formatRegExp, function(x) {
    if (x === '%%') return '%';
    if (i >= len) return x;
    switch (x) {
      case '%s': return String(args[i++]);
      case '%d': return Number(args[i++]);
      case '%j':
        try {
          return JSON.stringify(args[i++]);
        } catch (_) {
          return '[Circular]';
        }
      default:
        return x;
    }
  });
  for (var x = args[i]; i < len; x = args[++i]) {
    if (isNull(x) || !isObject(x)) {
      str += ' ' + x;
    } else {
      str += ' ' + inspect(x);
    }
  }
  return str;
};


// Mark that a method should not be used.
// Returns a modified function which warns once by default.
// If --no-deprecation is set, then it is a no-op.
exports.deprecate = function(fn, msg) {
  // Allow for deprecating things in the process of starting up.
  if (isUndefined(global.process)) {
    return function() {
      return exports.deprecate(fn, msg).apply(this, arguments);
    };
  }

  if (process.noDeprecation === true) {
    return fn;
  }

  var warned = false;
  function deprecated() {
    if (!warned) {
      if (process.throwDeprecation) {
        throw new Error(msg);
      } else if (process.traceDeprecation) {
        console.trace(msg);
      } else {
        console.error(msg);
      }
      warned = true;
    }
    return fn.apply(this, arguments);
  }

  return deprecated;
};


var debugs = {};
var debugEnviron;
exports.debuglog = function(set) {
  if (isUndefined(debugEnviron))
    debugEnviron = process.env.NODE_DEBUG || '';
  set = set.toUpperCase();
  if (!debugs[set]) {
    if (new RegExp('\\b' + set + '\\b', 'i').test(debugEnviron)) {
      var pid = process.pid;
      debugs[set] = function() {
        var msg = exports.format.apply(exports, arguments);
        console.error('%s %d: %s', set, pid, msg);
      };
    } else {
      debugs[set] = function() {};
    }
  }
  return debugs[set];
};


/**
 * Echos the value of a value. Trys to print the value out
 * in the best way possible given the different types.
 *
 * @param {Object} obj The object to print out.
 * @param {Object} opts Optional options object that alters the output.
 */
/* legacy: obj, showHidden, depth, colors*/
function inspect(obj, opts) {
  // default options
  var ctx = {
    seen: [],
    stylize: stylizeNoColor
  };
  // legacy...
  if (arguments.length >= 3) ctx.depth = arguments[2];
  if (arguments.length >= 4) ctx.colors = arguments[3];
  if (isBoolean(opts)) {
    // legacy...
    ctx.showHidden = opts;
  } else if (opts) {
    // got an "options" object
    exports._extend(ctx, opts);
  }
  // set default options
  if (isUndefined(ctx.showHidden)) ctx.showHidden = false;
  if (isUndefined(ctx.depth)) ctx.depth = 2;
  if (isUndefined(ctx.colors)) ctx.colors = false;
  if (isUndefined(ctx.customInspect)) ctx.customInspect = true;
  if (ctx.colors) ctx.stylize = stylizeWithColor;
  return formatValue(ctx, obj, ctx.depth);
}
exports.inspect = inspect;


// http://en.wikipedia.org/wiki/ANSI_escape_code#graphics
inspect.colors = {
  'bold' : [1, 22],
  'italic' : [3, 23],
  'underline' : [4, 24],
  'inverse' : [7, 27],
  'white' : [37, 39],
  'grey' : [90, 39],
  'black' : [30, 39],
  'blue' : [34, 39],
  'cyan' : [36, 39],
  'green' : [32, 39],
  'magenta' : [35, 39],
  'red' : [31, 39],
  'yellow' : [33, 39]
};

// Don't use 'blue' not visible on cmd.exe
inspect.styles = {
  'special': 'cyan',
  'number': 'yellow',
  'boolean': 'yellow',
  'undefined': 'grey',
  'null': 'bold',
  'string': 'green',
  'date': 'magenta',
  // "name": intentionally not styling
  'regexp': 'red'
};


function stylizeWithColor(str, styleType) {
  var style = inspect.styles[styleType];

  if (style) {
    return '\u001b[' + inspect.colors[style][0] + 'm' + str +
           '\u001b[' + inspect.colors[style][1] + 'm';
  } else {
    return str;
  }
}


function stylizeNoColor(str, styleType) {
  return str;
}


function arrayToHash(array) {
  var hash = {};

  array.forEach(function(val, idx) {
    hash[val] = true;
  });

  return hash;
}


function formatValue(ctx, value, recurseTimes) {
  // Provide a hook for user-specified inspect functions.
  // Check that value is an object with an inspect function on it
  if (ctx.customInspect &&
      value &&
      isFunction(value.inspect) &&
      // Filter out the util module, it's inspect function is special
      value.inspect !== exports.inspect &&
      // Also filter out any prototype objects using the circular check.
      !(value.constructor && value.constructor.prototype === value)) {
    var ret = value.inspect(recurseTimes, ctx);
    if (!isString(ret)) {
      ret = formatValue(ctx, ret, recurseTimes);
    }
    return ret;
  }

  // Primitive types cannot have properties
  var primitive = formatPrimitive(ctx, value);
  if (primitive) {
    return primitive;
  }

  // Look up the keys of the object.
  var keys = Object.keys(value);
  var visibleKeys = arrayToHash(keys);

  if (ctx.showHidden) {
    keys = Object.getOwnPropertyNames(value);
  }

  // IE doesn't make error fields non-enumerable
  // http://msdn.microsoft.com/en-us/library/ie/dww52sbt(v=vs.94).aspx
  if (isError(value)
      && (keys.indexOf('message') >= 0 || keys.indexOf('description') >= 0)) {
    return formatError(value);
  }

  // Some type of object without properties can be shortcutted.
  if (keys.length === 0) {
    if (isFunction(value)) {
      var name = value.name ? ': ' + value.name : '';
      return ctx.stylize('[Function' + name + ']', 'special');
    }
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    }
    if (isDate(value)) {
      return ctx.stylize(Date.prototype.toString.call(value), 'date');
    }
    if (isError(value)) {
      return formatError(value);
    }
  }

  var base = '', array = false, braces = ['{', '}'];

  // Make Array say that they are Array
  if (isArray(value)) {
    array = true;
    braces = ['[', ']'];
  }

  // Make functions say that they are functions
  if (isFunction(value)) {
    var n = value.name ? ': ' + value.name : '';
    base = ' [Function' + n + ']';
  }

  // Make RegExps say that they are RegExps
  if (isRegExp(value)) {
    base = ' ' + RegExp.prototype.toString.call(value);
  }

  // Make dates with properties first say the date
  if (isDate(value)) {
    base = ' ' + Date.prototype.toUTCString.call(value);
  }

  // Make error with message first say the error
  if (isError(value)) {
    base = ' ' + formatError(value);
  }

  if (keys.length === 0 && (!array || value.length == 0)) {
    return braces[0] + base + braces[1];
  }

  if (recurseTimes < 0) {
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    } else {
      return ctx.stylize('[Object]', 'special');
    }
  }

  ctx.seen.push(value);

  var output;
  if (array) {
    output = formatArray(ctx, value, recurseTimes, visibleKeys, keys);
  } else {
    output = keys.map(function(key) {
      return formatProperty(ctx, value, recurseTimes, visibleKeys, key, array);
    });
  }

  ctx.seen.pop();

  return reduceToSingleString(output, base, braces);
}


function formatPrimitive(ctx, value) {
  if (isUndefined(value))
    return ctx.stylize('undefined', 'undefined');
  if (isString(value)) {
    var simple = '\'' + JSON.stringify(value).replace(/^"|"$/g, '')
                                             .replace(/'/g, "\\'")
                                             .replace(/\\"/g, '"') + '\'';
    return ctx.stylize(simple, 'string');
  }
  if (isNumber(value))
    return ctx.stylize('' + value, 'number');
  if (isBoolean(value))
    return ctx.stylize('' + value, 'boolean');
  // For some reason typeof null is "object", so special case here.
  if (isNull(value))
    return ctx.stylize('null', 'null');
}


function formatError(value) {
  return '[' + Error.prototype.toString.call(value) + ']';
}


function formatArray(ctx, value, recurseTimes, visibleKeys, keys) {
  var output = [];
  for (var i = 0, l = value.length; i < l; ++i) {
    if (hasOwnProperty(value, String(i))) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          String(i), true));
    } else {
      output.push('');
    }
  }
  keys.forEach(function(key) {
    if (!key.match(/^\d+$/)) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          key, true));
    }
  });
  return output;
}


function formatProperty(ctx, value, recurseTimes, visibleKeys, key, array) {
  var name, str, desc;
  desc = Object.getOwnPropertyDescriptor(value, key) || { value: value[key] };
  if (desc.get) {
    if (desc.set) {
      str = ctx.stylize('[Getter/Setter]', 'special');
    } else {
      str = ctx.stylize('[Getter]', 'special');
    }
  } else {
    if (desc.set) {
      str = ctx.stylize('[Setter]', 'special');
    }
  }
  if (!hasOwnProperty(visibleKeys, key)) {
    name = '[' + key + ']';
  }
  if (!str) {
    if (ctx.seen.indexOf(desc.value) < 0) {
      if (isNull(recurseTimes)) {
        str = formatValue(ctx, desc.value, null);
      } else {
        str = formatValue(ctx, desc.value, recurseTimes - 1);
      }
      if (str.indexOf('\n') > -1) {
        if (array) {
          str = str.split('\n').map(function(line) {
            return '  ' + line;
          }).join('\n').substr(2);
        } else {
          str = '\n' + str.split('\n').map(function(line) {
            return '   ' + line;
          }).join('\n');
        }
      }
    } else {
      str = ctx.stylize('[Circular]', 'special');
    }
  }
  if (isUndefined(name)) {
    if (array && key.match(/^\d+$/)) {
      return str;
    }
    name = JSON.stringify('' + key);
    if (name.match(/^"([a-zA-Z_][a-zA-Z_0-9]*)"$/)) {
      name = name.substr(1, name.length - 2);
      name = ctx.stylize(name, 'name');
    } else {
      name = name.replace(/'/g, "\\'")
                 .replace(/\\"/g, '"')
                 .replace(/(^"|"$)/g, "'");
      name = ctx.stylize(name, 'string');
    }
  }

  return name + ': ' + str;
}


function reduceToSingleString(output, base, braces) {
  var numLinesEst = 0;
  var length = output.reduce(function(prev, cur) {
    numLinesEst++;
    if (cur.indexOf('\n') >= 0) numLinesEst++;
    return prev + cur.replace(/\u001b\[\d\d?m/g, '').length + 1;
  }, 0);

  if (length > 60) {
    return braces[0] +
           (base === '' ? '' : base + '\n ') +
           ' ' +
           output.join(',\n  ') +
           ' ' +
           braces[1];
  }

  return braces[0] + base + ' ' + output.join(', ') + ' ' + braces[1];
}


// NOTE: These type checking functions intentionally don't use `instanceof`
// because it is fragile and can be easily faked with `Object.create()`.
function isArray(ar) {
  return Array.isArray(ar);
}
exports.isArray = isArray;

function isBoolean(arg) {
  return typeof arg === 'boolean';
}
exports.isBoolean = isBoolean;

function isNull(arg) {
  return arg === null;
}
exports.isNull = isNull;

function isNullOrUndefined(arg) {
  return arg == null;
}
exports.isNullOrUndefined = isNullOrUndefined;

function isNumber(arg) {
  return typeof arg === 'number';
}
exports.isNumber = isNumber;

function isString(arg) {
  return typeof arg === 'string';
}
exports.isString = isString;

function isSymbol(arg) {
  return typeof arg === 'symbol';
}
exports.isSymbol = isSymbol;

function isUndefined(arg) {
  return arg === void 0;
}
exports.isUndefined = isUndefined;

function isRegExp(re) {
  return isObject(re) && objectToString(re) === '[object RegExp]';
}
exports.isRegExp = isRegExp;

function isObject(arg) {
  return typeof arg === 'object' && arg !== null;
}
exports.isObject = isObject;

function isDate(d) {
  return isObject(d) && objectToString(d) === '[object Date]';
}
exports.isDate = isDate;

function isError(e) {
  return isObject(e) &&
      (objectToString(e) === '[object Error]' || e instanceof Error);
}
exports.isError = isError;

function isFunction(arg) {
  return typeof arg === 'function';
}
exports.isFunction = isFunction;

function isPrimitive(arg) {
  return arg === null ||
         typeof arg === 'boolean' ||
         typeof arg === 'number' ||
         typeof arg === 'string' ||
         typeof arg === 'symbol' ||  // ES6 symbol
         typeof arg === 'undefined';
}
exports.isPrimitive = isPrimitive;

exports.isBuffer = require('./support/isBuffer');

function objectToString(o) {
  return Object.prototype.toString.call(o);
}


function pad(n) {
  return n < 10 ? '0' + n.toString(10) : n.toString(10);
}


var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
              'Oct', 'Nov', 'Dec'];

// 26 Feb 16:19:34
function timestamp() {
  var d = new Date();
  var time = [pad(d.getHours()),
              pad(d.getMinutes()),
              pad(d.getSeconds())].join(':');
  return [d.getDate(), months[d.getMonth()], time].join(' ');
}


// log is just a thin wrapper to console.log that prepends a timestamp
exports.log = function() {
  console.log('%s - %s', timestamp(), exports.format.apply(exports, arguments));
};


/**
 * Inherit the prototype methods from one constructor into another.
 *
 * The Function.prototype.inherits from lang.js rewritten as a standalone
 * function (not on Function.prototype). NOTE: If this file is to be loaded
 * during bootstrapping this function needs to be rewritten using some native
 * functions as prototype setup using normal JavaScript does not work as
 * expected during bootstrapping (see mirror.js in r114903).
 *
 * @param {function} ctor Constructor function which needs to inherit the
 *     prototype.
 * @param {function} superCtor Constructor function to inherit prototype from.
 */
exports.inherits = require('inherits');

exports._extend = function(origin, add) {
  // Don't do anything if add isn't an object
  if (!add || !isObject(add)) return origin;

  var keys = Object.keys(add);
  var i = keys.length;
  while (i--) {
    origin[keys[i]] = add[keys[i]];
  }
  return origin;
};

function hasOwnProperty(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

}).call(this,require('_process'),typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./support/isBuffer":44,"_process":18,"inherits":43}]},{},[1]);

module.exports = function(grunt) {
    grunt.initConfig({
        patch: {
            patch_aes: {
                options: {
                    patch: 'aes.patch'
                },
                files: {
                    'node_modules/milagro-crypto-js/src/aes.js': 'node_modules/milagro-crypto-js/src/aes.js'
                }
            }
        },
        browserify: {
            benchmark: {
                src: ["benchmark/browser/Benchmark.js"],
                dest: "benchmark/browser/Benchmark.bundle.js",
                options: {
                    alias: [
                        './node_modules/milagro-crypto-js/src/aes.js:./aes',
                        './node_modules/milagro-crypto-js/src/big.js:./big',
                        './node_modules/milagro-crypto-js/src/ecdh.js:./ecdh',
                        './node_modules/milagro-crypto-js/src/ecp.js:./ecp',
                        './node_modules/milagro-crypto-js/src/ecp2.js:./ecp2',
                        './node_modules/milagro-crypto-js/src/ff.js:./ff',
                        './node_modules/milagro-crypto-js/src/fp.js:./fp',
                        './node_modules/milagro-crypto-js/src/fp2.js:./fp2',
                        './node_modules/milagro-crypto-js/src/fp4.js:./fp4',
                        './node_modules/milagro-crypto-js/src/fp12.js:./fp12',
                        './node_modules/milagro-crypto-js/src/gcm.js:./gcm',
                        './node_modules/milagro-crypto-js/src/hash256.js:./hash256',
                        './node_modules/milagro-crypto-js/src/hash384.js:./hash384',
                        './node_modules/milagro-crypto-js/src/hash512.js:./hash512',
                        './node_modules/milagro-crypto-js/src/mpin.js:./mpin',
                        './node_modules/milagro-crypto-js/src/newhope.js:./newhope',
                        './node_modules/milagro-crypto-js/src/nhs.js:./nhs',
                        './node_modules/milagro-crypto-js/src/pair.js:./pair',
                        './node_modules/milagro-crypto-js/src/rand.js:./rand',
                        './node_modules/milagro-crypto-js/src/rom_curve.js:./rom_curve',
                        './node_modules/milagro-crypto-js/src/rom_field.js:./rom_field',
                        './node_modules/milagro-crypto-js/src/rsa.js:./rsa',
                        './node_modules/milagro-crypto-js/src/sha3.js:./sha3',
                        './node_modules/milagro-crypto-js/src/uint64.js:./uint64'
                    ]
                }
            }
        }
    });

    grunt.loadNpmTasks('grunt-patcher');
    grunt.loadNpmTasks("grunt-browserify");
};
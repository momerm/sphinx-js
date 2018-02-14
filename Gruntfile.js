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
    });

    grunt.loadNpmTasks('grunt-patcher');
};
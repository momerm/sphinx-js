function MYRAND() {
    const POOL_LEN = 32;
    this.pool = new Uint8Array(POOL_LEN);
    this.pool_pos = POOL_LEN;

    this.getByte = function() {
        if(this.pool_pos === POOL_LEN) {
            window.crypto.getRandomValues(this.pool);
            this.pool_pos = 0;
        }

        return this.pool[this.pool_pos++];
    };
}
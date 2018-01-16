function test_group() {
    let G = new Group_ECC();
    let sec1 = G.gensecret();
    let sec2 = G.gensecret();
    let gen = G.g;

    console.assert(G.expon(G.expon(gen, sec1), sec2).equals(G.expon(G.expon(gen, sec2), sec1)));
    console.assert(G.expon(G.expon(gen, sec1), sec2).equals(G.multiexpon(gen, [sec2, sec1])));
    console.assert(G.in_group(G.expon(gen, sec1))); // not working
}

function test_params() {
    // Test Init
    let params = new SphinxParams();

    let rand = new Uint8Array(16);
    window.crypto.getRandomValues(rand);
    let k = Array.from(rand);

    // Test AES
    let m = "Hello World!";
    let c = params.aes_ctr(k, stringtobytes(m));
    let m2 = bytestostring(params.aes_ctr(k, c));
    console.assert(m === m2);

    // Test Lioness
    m = "ARG".repeat(16);
    c = params.lioness_enc(k, stringtobytes(m));
    m2 = bytestostring(params.lioness_dec(k, c));
    console.assert(m === m2);
}
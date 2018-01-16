function test_minimal() {
    let r = 5;
    let params = new SphinxParams();

    // The minimal PKI involves names of nodes and keys

    let pkiPriv = {};
    let pkiPub = {};

    for(let nid = 0; nid < 10; nid++) {
        let x = params.group.gensecret();
        let y = params.group.expon(params.group.g, x);
        pkiPriv[nid] = new Pki_entry(nid, x, y);
        pkiPub[nid] = new Pki_entry(nid, null, y);
    }

    // The simplest path selection algorithm and message packaging

    let use_nodes = rand_subset(Object.getOwnPropertyNames(pkiPub), r);
    let nodes_routing = use_nodes.map(n => nenc(n));
    let node_keys = use_nodes.map(n => pkiPub[n].y);
    let dest = stringtobytes("bob");
    let message = stringtobytes("this is a test");
    let [header, delta] = create_forward_message(params, nodes_routing, node_keys, dest, message);

    // Test encoding and decoding

    let bin_message = pack_message(params, [header, delta]);
    let lens = JSON.stringify([params.max_len, params.m]);
    let param_dict = {};
    param_dict[lens] = params;

    let [px, [header1, delta1]] = unpack_message(param_dict, bin_message);
    console.assert(px === params);
    console.assert(JSON.stringify(header) === JSON.stringify(header1));
    console.assert(JSON.stringify(delta) === JSON.stringify(delta1));

    // Process message by the sequence of mixes
    let x = pkiPriv[use_nodes[0]].x;

    let i = 0;
    while (true) {
        let tag, B;
        [tag, B, [header, delta]] = sphinx_process(params, x, header, delta);
        let routing = route_unpack(B);

        console.log("round " + i);
        i++;

        if (routing[0] === Relay_flag) {
            let addr = routing[1];
            x = pkiPriv[addr].x;
        }
        else if (routing[0] === Dest_flag) {
            console.assert(routing[1] === null);
            for(let j = 0; j < 16; j++) {
                console.assert(delta[j] === 0);
            }
            let [dec_dest, dec_msg] = receive_forward(params, delta);
            console.assert(bytestostring(dec_dest) === bytestostring(dest));
            console.assert(bytestostring(dec_msg) === bytestostring(message));
            break;
        }
        else {
            console.log("Error");
            console.assert(false);
            break;
        }
    }

    // Test the nym creation
    let [surbid, surbkeytuple, nymtuple] = create_surb(params, nodes_routing, node_keys, stringtobytes("myself"));

    message = stringtobytes("This is a reply");
    [header, delta] = package_surb(params, nymtuple, message);

    x = pkiPriv[use_nodes[0]].x;

    while (true) {
        let tag, B;
        [tag, B, [header, delta]] = sphinx_process(params, x, header, delta);
        let routing = route_unpack(B);

        if (routing[0] === Relay_flag) {
            let addr = routing[1];
            x = pkiPriv[addr].x;
        }
        else if (routing[0] === Surb_flag) {
            let [flag, dest, myid ] = routing;
            break;
        }
    }

    let received = receive_surb(params, surbkeytuple, delta);
    console.assert(bytestostring(received) === bytestostring(message));
}

function test_timing() {
    let r = 5;
    let params = new SphinxParams();

    // The minimal PKI involves names of nodes and keys

    let pkiPriv = {};
    let pkiPub = {};

    for(let nid = 0; nid < 10; nid++) {
        let x = params.group.gensecret();
        let y = params.group.expon(params.group.g, x);
        pkiPriv[nid] = new Pki_entry(nid, x, y);
        pkiPub[nid] = new Pki_entry(nid, null, y);
    }

    let use_nodes = rand_subset(Object.getOwnPropertyNames(pkiPub), r);
    let nodes_routing = use_nodes.map(n => nenc(n));
    let node_keys = use_nodes.map(n => pkiPub[n].y);


    let header, delta;
    let dest = stringtobytes("dest");
    let message = stringtobytes("this is a test");
    console.time("mix encoding");
    for(let i = 0; i < 100; i++) {
        [header, delta] = create_forward_message(params, nodes_routing, node_keys, dest, message);
    }
    console.timeEnd("mix encoding");

    console.time("mix processing");
    for(let i = 0; i < 100; i++) {
        let x = pkiPriv[use_nodes[0]].x;
        sphinx_process(params, x, header, delta);
    }
    console.timeEnd("mix processing");
}
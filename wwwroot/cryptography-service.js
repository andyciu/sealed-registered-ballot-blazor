window.SRBB_generateKey_RSA = async function () {
    let keypair = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048, //can be 1024, 2048, or 4096
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: "SHA-256" }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
        },
        true, //whether the key is extractable (i.e. can be used in exportKey)
        ["encrypt", "decrypt"] //must be ["encrypt", "decrypt"] or ["wrapKey", "unwrapKey"]
    )
    let publickeyData = await crypto.subtle.exportKey(
        "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
        keypair.publicKey //can be a publicKey or privateKey, as long as extractable was true
    )
    let privatekeyData = await crypto.subtle.exportKey(
        "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
        keypair.privateKey //can be a publicKey or privateKey, as long as extractable was true
    )
    return {
        PublicKey: btoa(JSON.stringify(publickeyData)),
        PrivateKey: btoa(JSON.stringify(privatekeyData))
    }
}

window.SRBB_encrypt_RSA = async function (key, data) {
    let tmppublickeyObj = JSON.parse(atob(key));
    let publicKey = await crypto.subtle.importKey(
        "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
        tmppublickeyObj,
        {   //these are the algorithm options
            name: "RSA-OAEP",
            hash: { name: "SHA-256" }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
        },
        false, //whether the key is extractable (i.e. can be used in exportKey)
        ["encrypt"] //"encrypt" or "wrapKey" for public key import or
        //"decrypt" or "unwrapKey" for private key imports
    )

    let enc = new TextEncoder();
    let bufferdata = enc.encode(data);

    let encrypteddata = await crypto.subtle.encrypt(
        {
            name: "RSA-OAEP",
            //label: Uint8Array([...]) //optional
        },
        publicKey, //from generateKey or importKey above
        bufferdata //ArrayBuffer of data you want to encrypt
    )

    return new Uint8Array(encrypteddata);
}

window.SRBB_generateKey_AES = async function () {
    let key = await crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256, //can be  128, 192, or 256
        },
        true, //whether the key is extractable (i.e. can be used in exportKey)
        ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
    )
    let keyData = await crypto.subtle.exportKey(
        "jwk", //can be "jwk" or "raw"
        key //extractable must be true
    )
    return btoa(JSON.stringify(keyData))
}

window.SRBB_encrypt_AES = async function (key, data) {
    let tmpkeyObj = JSON.parse(atob(key));
    let keyData = await crypto.subtle.importKey(
        "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
        tmpkeyObj,
        {   //this is the algorithm options
            name: "AES-GCM",
        },
        false, //whether the key is extractable (i.e. can be used in exportKey)
        ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
    )

    let enc = new TextEncoder();
    let bufferdata = enc.encode(data);

    let encrypteddata = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",

            //Don't re-use initialization vectors!
            //Always generate a new iv every time your encrypt!
            //Recommended to use 12 bytes length
            iv: window.crypto.getRandomValues(new Uint8Array(12)),

            //Additional authentication data (optional)
            additionalData: enc.encode("PEKOPEKO"),

            //Tag length (optional)
            tagLength: 128, //can be 32, 64, 96, 104, 112, 120 or 128 (default)
        },
        keyData, //from generateKey or importKey above
        bufferdata //ArrayBuffer of data you want to encrypt
    )

    return new Uint8Array(encrypteddata);
}
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const CryptoJS = require("crypto-js");
const {
  gostEngine,
  GostDigest,
  AlgorithmIndentifier,
} = require("node-gost-crypto");

const createSecret = () => {
    return authenticator.generateSecret();
};

const getKeyURI = (wallet, secret) => {
    const keyuri = authenticator.keyuri(wallet, 'D3fenders', secret);
    return keyuri;
}

const getQrCode = async (keyuri) => {
    const url = await QRCode.toDataURL(keyuri);
    return url;
};

const getToken = (secret) => {
    return generate("totp", secret, 0, 30, 6, "SHA1");
    // return authenticator.generate(secret);
}

const verifyCode = async (code, secret) => {
    if (!authenticator.check(code, secret)) {
        return false;
    }
    return true;
}

async function syncTimeWithGoogle() {
    try {
        const https = require('https');
        const options = {
            method: 'HEAD',
            hostname: 'www.google.com',
            path: '/generate_204',
        };

        const res = await new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
                resolve(res);
            });

            req.on('error', (error) => {
                reject(error);
            });

            req.end();
        });

        const date = res.headers['date'];
        if (!date) {
            return 'updateFailure';
        }
        const serverTime = new Date(date).getTime();
        const clientTime = new Date().getTime();
        const offset = Math.round((serverTime - clientTime) / 1000);

        return offset;
    } catch (error) {
        throw error;
    }
}

function dec2hex(s) {
    return (s < 15.5 ? "0" : "") + Math.round(s).toString(16);
}

function hex2dec(s) {
    return Number(`0x${s}`);
}

function hex2str(hex) {
    let str = "";
    for (let i = 0; i < hex.length; i += 2) {
        str += String.fromCharCode(hex2dec(hex.substr(i, 2)));
    }
    return str;
}

function leftpad(str, len, pad) {
    if (len + 1 >= str.length) {
        str = new Array(len + 1 - str.length).join(pad) + str;
    }
    return str;
}

function base32tohex(base32) {
    const base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "";
    let hex = "";
    let padding = 0;

    for (let i = 0; i < base32.length; i++) {
        if (base32.charAt(i) === "=") {
            bits += "00000";
            padding++;
        } else {
            const val = base32chars.indexOf(base32.charAt(i).toUpperCase());
            bits += leftpad(val.toString(2), 5, "0");
        }
    }

    for (let i = 0; i + 4 <= bits.length; i += 4) {
        const chunk = bits.substr(i, 4);
        hex = hex + Number(`0b${chunk}`).toString(16);
    }

    switch (padding) {
    case 0:
        break;
    case 6:
        hex = hex.substr(0, hex.length - 8);
        break;
    case 4:
        hex = hex.substr(0, hex.length - 6);
        break;
    case 3:
        hex = hex.substr(0, hex.length - 4);
        break;
    case 1:
        hex = hex.substr(0, hex.length - 2);
        break;
    default:
        throw new Error("Invalid Base32 string");
    }

    return hex;
}

function base26(num) {
    const chars = "23456789BCDFGHJKMNPQRTVWXY";
    let output = "";
    const len = 5;
    for (let i = 0; i < len; i++) {
        output += chars[num % chars.length];
        num = Math.floor(num / chars.length);
    }
    if (output.length < len) {
        output = new Array(len - output.length + 1).join(chars[0]) + output;
    }
    return output;
}

function cryptoJsWordArrayToUint8Array(wordArray) {
    const l = wordArray.sigBytes;
    const words = wordArray.words;
    const result = new Uint8Array(l);
    let i = 0 /*dst*/,
    j = 0; /*src*/
    while (i < l) {
        // here i is a multiple of 4
        const w = words[j++];
        result[i++] = (w & 0xff000000) >>> 24;
        if (i === l) break;
        result[i++] = (w & 0x00ff0000) >>> 16;
        if (i === l) break;
        result[i++] = (w & 0x0000ff00) >>> 8;
        if (i === l) break;
        result[i++] = w & 0x000000ff;
    }
    return result;
}

function generate(
    type="totp",
    secret,
    counter=0,
    period=30,
    len=6,
    algorithm="SHA1"
) {
    console.log("Generate Token: ", global.systemOffset);

    secret = secret.replace(/\s/g, "");
    if (!len) {
        len = 6;
    }
    let b26 = false;
    let key;
    switch (type) {
        case "totp":
        case "hotp":
            key = base32tohex(secret);
            break;
        case "hex":
        case "hhex":
            key = secret;
            break;
        case "battle":
            key = base32tohex(secret);
            len = 8;
            break;
        case "steam":
            key = base32tohex(secret);
            len = 10;
            b26 = true;
            break;
        default:
            key = base32tohex(secret);
    }

    if (!key) {
        throw new Error("Invalid secret key");
    }

    if (type !== "hotp" && type !== "hhex") {
        let epoch = Math.round(new Date().getTime() / 1000.0);
        if (global.systemOffset) {
            epoch = epoch + Number(global.systemOffset);
        }
        counter = Math.floor(epoch / period);
    }

    const time = leftpad(dec2hex(counter), 16, "0");

    if (key.length % 2 === 1) {
        if (key.substr(-1) === "0") {
            key = key.substr(0, key.length - 1);
        } else {
            key += "0";
        }
    }

    let alg;
    let gostCipher;

    let hmacObj;
    switch (algorithm) {
        case "SHA256":
            hmacObj = CryptoJS.HmacSHA256(
                CryptoJS.enc.Hex.parse(time),
                CryptoJS.enc.Hex.parse(key)
            );
            break;
        case "SHA512":
            hmacObj = CryptoJS.HmacSHA512(
                CryptoJS.enc.Hex.parse(time),
                CryptoJS.enc.Hex.parse(key)
            );
            break;
        case "GOST3411_2012_256":
        case "GOST3411_2012_512":
            alg = {
                mode: "HMAC",
                name: "GOST R 34.11",
                version: 2012,
                length: OTPUtil.getOTPAlgorithmSpec(algorithm).length,
            };
            gostCipher = gostEngine.getGostDigest(alg);
            hmacObj = CryptoJS.lib.WordArray.create(
                gostCipher.sign(
                    cryptoJsWordArrayToUint8Array(CryptoJS.enc.Hex.parse(key)),
                    cryptoJsWordArrayToUint8Array(CryptoJS.enc.Hex.parse(time))
                )
            );
            break;
        default:
            hmacObj = CryptoJS.HmacSHA1(
                CryptoJS.enc.Hex.parse(time),
                CryptoJS.enc.Hex.parse(key)
            );
            break;
    }

    const hmac = CryptoJS.enc.Hex.stringify(hmacObj);

    const offset = hex2dec(hmac.substring(hmac.length - 1));

    let otp = (hex2dec(hmac.substr(offset * 2, 8)) & hex2dec("7fffffff")) + "";

    if (b26) {
        return base26(Number(otp));
    }

    if (otp.length < len) {
        otp = new Array(len - otp.length + 1).join("0") + otp;
    }

    return otp.substr(otp.length - len, len).toString();
}

(async () => {
    const offset = await syncTimeWithGoogle();
    global.systemOffset = offset;
})();

module.exports = {
    createSecret,
    getQrCode,
    verifyCode,
    getToken,
    getKeyURI
};
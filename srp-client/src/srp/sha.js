/**
 *
 *  Secure Hash Algorithm (SHA256)
 *  http://www.webtoolkit.info/
 *
 *  Original code by Angel Marin, Paul Johnston.
 *
 **/

function SHA256(s) {

    var chrsz = 8;
    var hexcase = 0;

    function safe_add(x, y) {
        var lsw = (x & 0xFFFF) + (y & 0xFFFF);
        var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return (msw << 16) | (lsw & 0xFFFF);
    }

    function S(X, n) {
        return ( X >>> n ) | (X << (32 - n));
    }

    function R(X, n) {
        return ( X >>> n );
    }

    function Ch(x, y, z) {
        return ((x & y) ^ ((~x) & z));
    }

    function Maj(x, y, z) {
        return ((x & y) ^ (x & z) ^ (y & z));
    }

    function Sigma0256(x) {
        return (S(x, 2) ^ S(x, 13) ^ S(x, 22));
    }

    function Sigma1256(x) {
        return (S(x, 6) ^ S(x, 11) ^ S(x, 25));
    }

    function Gamma0256(x) {
        return (S(x, 7) ^ S(x, 18) ^ R(x, 3));
    }

    function Gamma1256(x) {
        return (S(x, 17) ^ S(x, 19) ^ R(x, 10));
    }

    function core_sha256(m, l) {
        var K = new Array(0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0xFC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x6CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2);
        var HASH = new Array(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
        var W = new Array(64);
        var a, b, c, d, e, f, g, h, i, j;
        var T1, T2;

        m[l >> 5] |= 0x80 << (24 - l % 32);
        m[((l + 64 >> 9) << 4) + 15] = l;

        for (var i = 0; i < m.length; i += 16) {
            a = HASH[0];
            b = HASH[1];
            c = HASH[2];
            d = HASH[3];
            e = HASH[4];
            f = HASH[5];
            g = HASH[6];
            h = HASH[7];

            for (var j = 0; j < 64; j++) {
                if (j < 16) {
                    W[j] = m[j + i];
                }
                else {
                    W[j] = safe_add(safe_add(safe_add(Gamma1256(W[j - 2]), W[j - 7]), Gamma0256(W[j - 15])), W[j - 16]);
                }

                T1 = safe_add(safe_add(safe_add(safe_add(h, Sigma1256(e)), Ch(e, f, g)), K[j]), W[j]);
                T2 = safe_add(Sigma0256(a), Maj(a, b, c));

                h = g;
                g = f;
                f = e;
                e = safe_add(d, T1);
                d = c;
                c = b;
                b = a;
                a = safe_add(T1, T2);
            }

            HASH[0] = safe_add(a, HASH[0]);
            HASH[1] = safe_add(b, HASH[1]);
            HASH[2] = safe_add(c, HASH[2]);
            HASH[3] = safe_add(d, HASH[3]);
            HASH[4] = safe_add(e, HASH[4]);
            HASH[5] = safe_add(f, HASH[5]);
            HASH[6] = safe_add(g, HASH[6]);
            HASH[7] = safe_add(h, HASH[7]);
        }
        return HASH;
    }

    function str2binb(str) {
        var bin = Array();
        var mask = (1 << chrsz) - 1;
        for (var i = 0; i < str.length * chrsz; i += chrsz) {
            bin[i >> 5] |= (str.charCodeAt(i / chrsz) & mask) << (24 - i % 32);
        }
        return bin;
    }

    function Utf8Encode(string) {
        string = string.replace(/\r\n/g, "\n");
        var utftext = "";

        for (var n = 0; n < string.length; n++) {

            var c = string.charCodeAt(n);

            if (c < 128) {
                utftext += String.fromCharCode(c);
            }
            else if ((c > 127) && (c < 2048)) {
                utftext += String.fromCharCode((c >> 6) | 192);
                utftext += String.fromCharCode((c & 63) | 128);
            }
            else {
                utftext += String.fromCharCode((c >> 12) | 224);
                utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                utftext += String.fromCharCode((c & 63) | 128);
            }

        }

        return utftext;
    }

    function binb2hex(binarray) {
        var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
        var str = "";
        for (var i = 0; i < binarray.length * 4; i++) {
            str += hex_tab.charAt((binarray[i >> 2] >> ((3 - i % 4) * 8 + 4)) & 0xF) +
                hex_tab.charAt((binarray[i >> 2] >> ((3 - i % 4) * 8  )) & 0xF);
        }
        return str;
    }

    s = Utf8Encode(s);
    return binb2hex(core_sha256(str2binb(s), s.length * chrsz));

}


/*
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined
 * in FIPS PUB 180-1
 * Copyright (C) Paul Johnston 2000.
 * See http://pajhome.org.uk/site/legal.html for details.
 */
/*
 * Modified by Tom Wu (tjw@cs.stanford.edu) for the
 * SRP JavaScript implementation.
 */

/*
 * Convert a 32-bit number to a hex string with ms-byte first
 */
var hex_chr = "0123456789abcdef";
function hex(num) {
    var str = "";
    for (var j = 7; j >= 0; j--)
        str += hex_chr.charAt((num >> (j * 4)) & 0x0F);
    return str;
}

/*
 * Convert a string to a sequence of 16-word blocks, stored as an array.
 * Append padding bits and the length, as described in the SHA1 standard.
 */
function str2blks_SHA1(str) {
    var nblk = ((str.length + 8) >> 6) + 1;
    var blks = new Array(nblk * 16);
    for (var i = 0; i < nblk * 16; i++) blks[i] = 0;
    for (i = 0; i < str.length; i++)
        blks[i >> 2] |= str.charCodeAt(i) << (24 - (i % 4) * 8);
    blks[i >> 2] |= 0x80 << (24 - (i % 4) * 8);
    blks[nblk * 16 - 1] = str.length * 8;
    return blks;
}

/*
 * Input is in hex format - trailing odd nibble gets a zero appended.
 */
function hex2blks_SHA1(hex) {
    var len = (hex.length + 1) >> 1;
    var nblk = ((len + 8) >> 6) + 1;
    var blks = new Array(nblk * 16);
    for (var i = 0; i < nblk * 16; i++) blks[i] = 0;
    for (i = 0; i < len; i++)
        blks[i >> 2] |= parseInt(hex.substr(2 * i, 2), 16) << (24 - (i % 4) * 8);
    blks[i >> 2] |= 0x80 << (24 - (i % 4) * 8);
    blks[nblk * 16 - 1] = len * 8;
    return blks;
}

function ba2blks_SHA1(ba, off, len) {
    var nblk = ((len + 8) >> 6) + 1;
    var blks = new Array(nblk * 16);
    for (var i = 0; i < nblk * 16; i++) blks[i] = 0;
    for (i = 0; i < len; i++)
        blks[i >> 2] |= (ba[off + i] & 0xFF) << (24 - (i % 4) * 8);
    blks[i >> 2] |= 0x80 << (24 - (i % 4) * 8);
    blks[nblk * 16 - 1] = len * 8;
    return blks;
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function sha1_add(x, y) {
    var lsw = (x & 0xFFFF) + (y & 0xFFFF);
    var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left
 */
function rol(num, cnt) {
    return (num << cnt) | (num >>> (32 - cnt));
}

/*
 * Perform the appropriate triplet combination function for the current
 * iteration
 */
function ft(t, b, c, d) {
    if (t < 20) {
        return (b & c) | ((~b) & d);
    }
    if (t < 40) {
        return b ^ c ^ d;
    }
    if (t < 60) {
        return (b & c) | (b & d) | (c & d);
    }
    return b ^ c ^ d;
}

/*
 * Determine the appropriate additive constant for the current iteration
 */
function kt(t) {
    return (t < 20) ? 1518500249 : (t < 40) ? 1859775393 :
        (t < 60) ? -1894007588 : -899497514;
}

/*
 * Take a string and return the hex representation of its SHA-1.
 */
// this function does not works with utf8 string
function bad_calcSHA1(str) {
    return calcSHA1Blks(str2blks_SHA1(str));
}

function calcSHA1Hex(str) {
    return calcSHA1Blks(hex2blks_SHA1(str));
}

function calcSHA1BA(ba) {
    return calcSHA1Blks(ba2blks_SHA1(ba, 0, ba.length));
}

function calcSHA1BAEx(ba, off, len) {
    return calcSHA1Blks(ba2blks_SHA1(ba, off, len));
}

function calcSHA1Blks(x) {
    var s = calcSHA1Raw(x);
    return hex(s[0]) + hex(s[1]) + hex(s[2]) + hex(s[3]) + hex(s[4]);
}

function calcSHA1Raw(x) {
    var w = new Array(80);

    var a = 1732584193;
    var b = -271733879;
    var c = -1732584194;
    var d = 271733878;
    var e = -1009589776;

    for (var i = 0; i < x.length; i += 16) {
        var olda = a;
        var oldb = b;
        var oldc = c;
        var oldd = d;
        var olde = e;

        for (var j = 0; j < 80; j++) {
            var t;
            if (j < 16) {
                w[j] = x[i + j];
            }
            else {
                w[j] = rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
            }
            t = sha1_add(sha1_add(rol(a, 5), ft(j, b, c, d)), sha1_add(sha1_add(e, w[j]), kt(j)));
            e = d;
            d = c;
            c = rol(b, 30);
            b = a;
            a = t;
        }

        a = sha1_add(a, olda);
        b = sha1_add(b, oldb);
        c = sha1_add(c, oldc);
        d = sha1_add(d, oldd);
        e = sha1_add(e, olde);
    }
    return new Array(a, b, c, d, e);
}

function core_sha1(x, len) {
    x[len >> 5] |= 0x80 << (24 - len % 32);
    x[((len + 64 >> 9) << 4) + 15] = len;
    return calcSHA1Raw(x);
}


///
/**
 * jQuery SHA1 hash algorithm function
 *
 *      <code>
 *              Calculate the sha1 hash of a String
 *              String $.sha1 ( String str )
 *      </code>
 *
 * Calculates the sha1 hash of str using the US Secure Hash Algorithm 1.
 * SHA-1 the Secure Hash Algorithm (SHA) was developed by NIST and is specified in the Secure Hash Standard (SHS, FIPS 180).
 * This script is used to process variable length message into a fixed-length output using the SHA-1 algorithm. It is fully compatible with UTF-8 encoding.
 * If you plan using UTF-8 encoding in your project don't forget to set the page encoding to UTF-8 (Content-Type meta tag).
 * This function orginally get from the WebToolkit and rewrite for using as the jQuery plugin.
 *
 * Example
 *      Code
 *              <code>
 *                      $.sha1("I'm Persian.");
 *              </code>
 *      Result
 *              <code>
 *                      "1d302f9dc925d62fc859055999d2052e274513ed"
 *              </code>
 *
 * @alias Muhammad Hussein Fattahizadeh < muhammad [AT] semnanweb [DOT] com >
 * @link http://www.semnanweb.com/jquery-plugin/sha1.html
 * @see http://www.webtoolkit.info/
 * @license http://www.gnu.org/licenses/gpl.html [GNU General Public License]
 * @param {jQuery} {sha1:function(string))
 * @return string
 */


var rotateLeft = function (lValue, iShiftBits) {
    return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
};

var lsbHex = function (value) {
    var string = "";
    var i;
    var vh;
    var vl;
    for (i = 0; i <= 6; i += 2) {
        vh = (value >>> (i * 4 + 4)) & 0x0f;
        vl = (value >>> (i * 4)) & 0x0f;
        string += vh.toString(16) + vl.toString(16);
    }
    return string;
};

var cvtHex = function (value) {
    var string = "";
    var i;
    var v;
    for (i = 7; i >= 0; i--) {
        v = (value >>> (i * 4)) & 0x0f;
        string += v.toString(16);
    }
    return string;
};

var uTF8Encode = function (string) {
    string = string.replace(/\x0d\x0a/g, "\x0a");
    var output = "";
    for (var n = 0; n < string.length; n++) {
        var c = string.charCodeAt(n);
        if (c < 128) {
            output += String.fromCharCode(c);
        } else if ((c > 127) && (c < 2048)) {
            output += String.fromCharCode((c >> 6) | 192);
            output += String.fromCharCode((c & 63) | 128);
        } else {
            output += String.fromCharCode((c >> 12) | 224);
            output += String.fromCharCode(((c >> 6) & 63) | 128);
            output += String.fromCharCode((c & 63) | 128);
        }
    }
    return output;
};

function calcSHA1(string, win1251) {
    var blockstart;
    var i, j;
    var W = new Array(80);
    var H0 = 0x67452301;
    var H1 = 0xEFCDAB89;
    var H2 = 0x98BADCFE;
    var H3 = 0x10325476;
    var H4 = 0xC3D2E1F0;
    var A, B, C, D, E;
    var tempValue;
    string = win1251 ? UnicodeToWin1251(string) : uTF8Encode(string);
    /*
     if (win1251) {
     string = UnicodeToWin1251(string);
     } else {
     string = uTF8Encode(string);
     }*/
    var stringLength = string.length;
    var wordArray = new Array();
    for (i = 0; i < stringLength - 3; i += 4) {
        j = string.charCodeAt(i) << 24 | string.charCodeAt(i + 1) << 16 | string.charCodeAt(i + 2) << 8 | string.charCodeAt(i + 3);
        wordArray.push(j);
    }
    switch (stringLength % 4) {
        case 0:
            i = 0x080000000;
            break;
        case 1:
            i = string.charCodeAt(stringLength - 1) << 24 | 0x0800000;
            break;
        case 2:
            i = string.charCodeAt(stringLength - 2) << 24 | string.charCodeAt(stringLength - 1) << 16 | 0x08000;
            break;
        case 3:
            i = string.charCodeAt(stringLength - 3) << 24 | string.charCodeAt(stringLength - 2) << 16 | string.charCodeAt(stringLength - 1) << 8 | 0x80;
            break;
    }
    wordArray.push(i);
    while ((wordArray.length % 16) != 14) wordArray.push(0);
    wordArray.push(stringLength >>> 29);
    wordArray.push((stringLength << 3) & 0x0ffffffff);
    for (blockstart = 0; blockstart < wordArray.length; blockstart += 16) {
        for (i = 0; i < 16; i++) W[i] = wordArray[blockstart + i];
        for (i = 16; i <= 79; i++) W[i] = rotateLeft(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
        A = H0;
        B = H1;
        C = H2;
        D = H3;
        E = H4;
        for (i = 0; i <= 19; i++) {
            tempValue = (rotateLeft(A, 5) + ((B & C) | (~B & D)) + E + W[i] + 0x5A827999) & 0x0ffffffff;
            E = D;
            D = C;
            C = rotateLeft(B, 30);
            B = A;
            A = tempValue;
        }
        for (i = 20; i <= 39; i++) {
            tempValue = (rotateLeft(A, 5) + (B ^ C ^ D) + E + W[i] + 0x6ED9EBA1) & 0x0ffffffff;
            E = D;
            D = C;
            C = rotateLeft(B, 30);
            B = A;
            A = tempValue;
        }
        for (i = 40; i <= 59; i++) {
            tempValue = (rotateLeft(A, 5) + ((B & C) | (B & D) | (C & D)) + E + W[i] + 0x8F1BBCDC) & 0x0ffffffff;
            E = D;
            D = C;
            C = rotateLeft(B, 30);
            B = A;
            A = tempValue;
        }
        for (i = 60; i <= 79; i++) {
            tempValue = (rotateLeft(A, 5) + (B ^ C ^ D) + E + W[i] + 0xCA62C1D6) & 0x0ffffffff;
            E = D;
            D = C;
            C = rotateLeft(B, 30);
            B = A;
            A = tempValue;
        }
        H0 = (H0 + A) & 0x0ffffffff;
        H1 = (H1 + B) & 0x0ffffffff;
        H2 = (H2 + C) & 0x0ffffffff;
        H3 = (H3 + D) & 0x0ffffffff;
        H4 = (H4 + E) & 0x0ffffffff;
    }
    var tempValue = cvtHex(H0) + cvtHex(H1) + cvtHex(H2) + cvtHex(H3) + cvtHex(H4);
    return tempValue.toLowerCase();
};


function btoa(bin) {
    var tableStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var table = tableStr.split("");
    for (var i = 0, j = 0, len = bin.length / 3, base64 = []; i < len; ++i) {
        var a = bin.charCodeAt(j++), b = bin.charCodeAt(j++), c = bin.charCodeAt(j++);
        if ((a | b | c) > 255) throw new Error("String contains an invalid character");
        base64[base64.length] = table[a >> 2] + table[((a << 4) & 63) | (b >> 4)] +
            (isNaN(b) ? "=" : table[((b << 2) & 63) | (c >> 6)]) +
            (isNaN(b + c) ? "=" : table[c & 63]);
    }
    return base64.join("");
};


function hexToBase64(str) {
    return btoa(String.fromCharCode.apply(null,
        str.replace(/\r|\n/g, "").replace(/([\da-fA-F]{2}) ?/g, "0x$1 ").replace(/ +$/, "").split(" "))
    );
}

function UnicodeToWin1251(s) {
    var DMap = {
        0: 0,
        1: 1,
        2: 2,
        3: 3,
        4: 4,
        5: 5,
        6: 6,
        7: 7,
        8: 8,
        9: 9,
        10: 10,
        11: 11,
        12: 12,
        13: 13,
        14: 14,
        15: 15,
        16: 16,
        17: 17,
        18: 18,
        19: 19,
        20: 20,
        21: 21,
        22: 22,
        23: 23,
        24: 24,
        25: 25,
        26: 26,
        27: 27,
        28: 28,
        29: 29,
        30: 30,
        31: 31,
        32: 32,
        33: 33,
        34: 34,
        35: 35,
        36: 36,
        37: 37,
        38: 38,
        39: 39,
        40: 40,
        41: 41,
        42: 42,
        43: 43,
        44: 44,
        45: 45,
        46: 46,
        47: 47,
        48: 48,
        49: 49,
        50: 50,
        51: 51,
        52: 52,
        53: 53,
        54: 54,
        55: 55,
        56: 56,
        57: 57,
        58: 58,
        59: 59,
        60: 60,
        61: 61,
        62: 62,
        63: 63,
        64: 64,
        65: 65,
        66: 66,
        67: 67,
        68: 68,
        69: 69,
        70: 70,
        71: 71,
        72: 72,
        73: 73,
        74: 74,
        75: 75,
        76: 76,
        77: 77,
        78: 78,
        79: 79,
        80: 80,
        81: 81,
        82: 82,
        83: 83,
        84: 84,
        85: 85,
        86: 86,
        87: 87,
        88: 88,
        89: 89,
        90: 90,
        91: 91,
        92: 92,
        93: 93,
        94: 94,
        95: 95,
        96: 96,
        97: 97,
        98: 98,
        99: 99,
        100: 100,
        101: 101,
        102: 102,
        103: 103,
        104: 104,
        105: 105,
        106: 106,
        107: 107,
        108: 108,
        109: 109,
        110: 110,
        111: 111,
        112: 112,
        113: 113,
        114: 114,
        115: 115,
        116: 116,
        117: 117,
        118: 118,
        119: 119,
        120: 120,
        121: 121,
        122: 122,
        123: 123,
        124: 124,
        125: 125,
        126: 126,
        127: 127,
        1027: 129,
        8225: 135,
        1046: 198,
        8222: 132,
        1047: 199,
        1168: 165,
        1048: 200,
        1113: 154,
        1049: 201,
        1045: 197,
        1050: 202,
        1028: 170,
        160: 160,
        1040: 192,
        1051: 203,
        164: 164,
        166: 166,
        167: 167,
        169: 169,
        171: 171,
        172: 172,
        173: 173,
        174: 174,
        1053: 205,
        176: 176,
        177: 177,
        1114: 156,
        181: 181,
        182: 182,
        183: 183,
        8221: 148,
        187: 187,
        1029: 189,
        1056: 208,
        1057: 209,
        1058: 210,
        8364: 136,
        1112: 188,
        1115: 158,
        1059: 211,
        1060: 212,
        1030: 178,
        1061: 213,
        1062: 214,
        1063: 215,
        1116: 157,
        1064: 216,
        1065: 217,
        1031: 175,
        1066: 218,
        1067: 219,
        1068: 220,
        1069: 221,
        1070: 222,
        1032: 163,
        8226: 149,
        1071: 223,
        1072: 224,
        8482: 153,
        1073: 225,
        8240: 137,
        1118: 162,
        1074: 226,
        1110: 179,
        8230: 133,
        1075: 227,
        1033: 138,
        1076: 228,
        1077: 229,
        8211: 150,
        1078: 230,
        1119: 159,
        1079: 231,
        1042: 194,
        1080: 232,
        1034: 140,
        1025: 168,
        1081: 233,
        1082: 234,
        8212: 151,
        1083: 235,
        1169: 180,
        1084: 236,
        1052: 204,
        1085: 237,
        1035: 142,
        1086: 238,
        1087: 239,
        1088: 240,
        1089: 241,
        1090: 242,
        1036: 141,
        1041: 193,
        1091: 243,
        1092: 244,
        8224: 134,
        1093: 245,
        8470: 185,
        1094: 246,
        1054: 206,
        1095: 247,
        1096: 248,
        8249: 139,
        1097: 249,
        1098: 250,
        1044: 196,
        1099: 251,
        1111: 191,
        1055: 207,
        1100: 252,
        1038: 161,
        8220: 147,
        1101: 253,
        8250: 155,
        1102: 254,
        8216: 145,
        1103: 255,
        1043: 195,
        1105: 184,
        1039: 143,
        1026: 128,
        1106: 144,
        8218: 130,
        1107: 131,
        8217: 146,
        1108: 186,
        1109: 190
    }
    var L = [];
    for (var i = 0; i < s.length; i++) {
        var ord = s.charCodeAt(i);
        if (!(ord in DMap))
            throw "Character " + s.charAt(i) + " isn't supported by win1251!"
        L.push(String.fromCharCode(DMap[ord]))
    }
    return L.join('')
}

export {hexToBase64, calcSHA1, calcSHA1Hex};
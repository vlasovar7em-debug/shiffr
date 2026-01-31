// ===== ELEMENTS =====
const menuItems = document.querySelectorAll(".menu__item");
console.log(menuItems);
const title = document.getElementById("tool-title");
const desc = document.getElementById("tool-desc");

const input = document.getElementById("input");
const output = document.getElementById("output");
const actionBtn = document.getElementById("action-btn");

const modeInputs = document.querySelectorAll("input[name='mode']");

// ===== WORDLIST / HASH MAPS =====
const WORDLISTURL = "wordlist.txt"; // файл с одним словом на строку (рекомендуется ~1000 строк)
let md5Map = Object.create(null);
let sha1Map = Object.create(null);
let sha256Map = Object.create(null);
let sha512Map = Object.create(null);
let sha3Map = Object.create(null);
let wordlistLoaded = false;

// Небольшой встроенный запас (на случай, если wordlist.txt не найден).
const fallbackWords = [
    "123456",
    "password",
    "12345678",
    "qwerty",
    "123456789",
    "12345",
    "1234",
    "111111",
    "1234567",
    "dragon",
    "123123",
    "baseball",
    "abc123",
    "football",
    "monkey",
    "letmein",
    "696969",
    "shadow",
    "master",
    "666666",
    "qwertyuiop",
    "123321",
    "mustang",
    "1234567890",
    "michael",
    "654321",
    "superman",
    "1qaz2wsx",
    "7777777",
    "fuckyou",
    "121212",
    "000000",
    "qazwsx",
    "123qwe",
    "killer",
    "trustno1",
    "jordan",
    "jennifer",
    "zxcvbnm",
    "asdfgh",
    "hunter",
    "buster",
    "soccer",
    "harley",
    "batman",
    "andrew",
    "tigger",
    "sunshine",
    "iloveyou",
    "2000",
    "charlie",
    "robert",
    "thomas",
    "hannah",
];

// Загружает список слов из файла, или использует fallback.
async function loadWordlist() {
    let words = [];
    try {
        const res = await fetch(WORDLISTURL, { cache: "no-store" });
        if (!res.ok) throw new Error("Нет wordlist.txt");
        const text = await res.text();
        words = text
            .split(/\r?\n/)
            .map((w) => w.trim())
            .filter(Boolean);
        if (words.length === 0) throw new Error("Пустой wordlist.txt");
        console.log(`Загружено ${words.length} слов из ${WORDLISTURL}`);
    } catch (err) {
        console.warn(
            "Не удалось загрузить wordlist.txt, используется встроенный список.",
            err,
        );
        words = fallbackWords;
    }

    // Ограничим количество (если файл очень большой), например до 10000, но обычно будет ~1000.
    const MAXWORDS = 20000;
    if (words.length > MAXWORDS) words = words.slice(0, MAXWORDS);
    md5Map = Object.create(null);
    sha1Map = Object.create(null);
    sha256Map = Object.create(null);
    sha512Map = Object.create(null);
    sha3Map = Object.create(null);

    for (const w of words) {
        const hmd5 = CryptoJS.MD5(w).toString().toLowerCase();
        const hsha1 = CryptoJS.SHA1(w).toString().toLowerCase();
        const hsha256 = CryptoJS.SHA256(w).toString().toLowerCase();
        const hsha512 = CryptoJS.SHA512(w).toString().toLowerCase();
        const hsha3 = CryptoJS.SHA3(w).toString().toLowerCase();
        // Сохраняем первый попавшийся (чтобы не перезаписывать при коллизиях)
        if (!md5Map[hmd5]) md5Map[hmd5] = w;
        if (!sha1Map[hsha1]) sha1Map[hsha1] = w;
        if (!sha256Map[hsha256]) sha256Map[hsha256] = w;
        if (!sha512Map[hsha512]) sha512Map[hsha512] = w;
        if (!sha3Map[hsha3]) sha3Map[hsha3] = w;
    }

    wordlistLoaded = true;
    console.log("Словари хешей готовы:", {
        md5: Object.keys(md5Map).length,
        sha1: Object.keys(sha1Map).length,
        sha256: Object.keys(sha256Map).length,
        sha512: Object.keys(sha512Map).length,
        sha3: Object.keys(sha3Map).length,
    });
}

// Старт загрузки словаря асинхронно
loadWordlist();

// ===== TOOL CONFIG =====
const tools = {
    base64: {
        title: "Base 64",
        desc: "Кодирование и декодирование текста в Base64",
        encode: (text) => btoa(unescape(encodeURIComponent(text))),
        decode: (text) => decodeURIComponent(escape(atob(text))),
        allowDecode: true,
        buildOptions: () => [],
    },
    md5: {
        title: "MD5",
        desc: "Хеширование текста с помощью MD5. Декодирование — поиск по словарю частых строк.",
        encode: (text) => CryptoJS.MD5(text).toString(),
        decode: (hash) => {
            if (!hash) return "Пустой хеш";
            const h = hash.trim().toLowerCase();
            if (!wordlistLoaded) {
                console.warn(
                    "Словарь ещё загружается, поиск будет произведён по доступным данным.",
                );
            }
            if (md5Map[h]) return md5Map[h];
            return "Не удалось декодировать (не найдено в словаре)";
        },
        allowDecode: true,
        buildOptions: () => [],
    },
    sha1: {
        title: "SHA1",
        desc: "Хеширование текста с помощью SHA1. Декодирование — поиск по словарю частых строк.",
        encode: (text) => CryptoJS.SHA1(text).toString(),
        decode: (hash) => {
            if (!hash) return "Пустой хеш";
            const h = hash.trim().toLowerCase();
            if (!wordlistLoaded) {
                console.warn(
                    "Словарь ещё загружается, поиск будет произведён по доступным данным.",
                );
            }
            if (sha1Map[h]) return sha1Map[h];
            return "Не удалось декодировать (не найдено в словаре)";
        },
        allowDecode: true,
        buildOptions: () => [],
    },
    sha256: {
        title: "SHA-256",
        desc: "Хеширование текста с помощью SHA-256. Декодирование — поиск по словарю частых строк.",
        encode: (text) => CryptoJS.SHA256(text).toString(),
        decode: (hash) => {
            if (!hash) return "Пустой хеш";
            const h = hash.trim().toLowerCase();
            if (!wordlistLoaded) {
                console.warn(
                    "Словарь ещё загружается, поиск будет произведён по доступным данным.",
                );
            }
            if (sha256Map[h]) return sha256Map[h];
            return "Не удалось декодировать (не найдено в словаре)";
        },
        allowDecode: true,
        buildOptions: () => [],
    },
    sha512: {
        title: "SHA-512",
        desc: "Хеширование текста с помощью SHA-512. Декодирование — поиск по словарю частых строк.",
        encode: (text) => CryptoJS.SHA512(text).toString(),
        decode: (hash) => {
            if (!hash) return "Пустой хеш";
            const h = hash.trim().toLowerCase();
            if (!wordlistLoaded) {
                console.warn(
                    "Словарь ещё загружается, поиск будет произведён по доступным данным.",
                );
            }
            if (sha512Map[h]) return sha512Map[h];
            return "Не удалось декодировать (не найдено в словаре)";
        },
        allowDecode: true,
        buildOptions: () => [],
    },
    sha3: {
        title: "SHA-3",
        desc: "Хеширование текста с помощью SHA-3. Декодирование — поиск по словарю частых строк.",
        encode: (text) => CryptoJS.SHA3(text).toString(),
        decode: (hash) => {
            if (!hash) return "Пустой хеш";
            const h = hash.trim().toLowerCase();
            if (!wordlistLoaded) {
                console.warn(
                    "Словарь ещё загружается, поиск будет произведён по доступным данным.",
                );
            }
            if (sha3Map[h]) return sha3Map[h];
            return "Не удалось декодировать (не найдено в словаре)";
        },
        allowDecode: true,
        buildOptions: () => [],
    },
    aes: {
        title: "AES",
        desc: "Симметричное шифрование AES (CBC, PKCS7). Используйте ключ и при необходимости IV.",
        allowDecode: true,
        buildOptions: (mode) => {
            return [
                {
                    id: "key",
                    label: "Ключ",
                    type: "text",
                    placeholder: "Строка или hex-ключ",
                },
                {
                    id: "iv",
                    label: "IV (hex, необязательно)",
                    type: "text",
                    placeholder: "Например: 000102030405060708090a0b0c0d0e0f",
                },
            ];
        },
        encode: (text, opts) => {
            const { key, iv } = opts;
            if (!key) throw new Error("Укажите ключ");

            // Подготовка ключа: hex с проверкой длины или SHA-256 от строки
            let keyWords;
            if (/^[0-9a-fA-F]+$/.test(key)) {
                if (![32, 48, 64].includes(key.length)) {
                    throw new Error(
                        "Длина hex-ключа должна быть 32/48/64 символа (16/24/32 байта)",
                    );
                }
                keyWords = CryptoJS.enc.Hex.parse(key);
            } else {
                keyWords = CryptoJS.SHA256(key);
            }

            const cfg = {
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7,
            };
            let usedIvHex = null;
            if (iv && iv.trim()) {
                const ivStr = iv.trim();
                if (!/^[0-9a-fA-F]+$/.test(ivStr) || ivStr.length % 2 !== 0) {
                    throw new Error("IV должен быть hex-строкой чётной длины");
                }
                cfg.iv = CryptoJS.enc.Hex.parse(ivStr);
            } else {
                // Сгенерируем случайный IV для шифрования
                const ivRand = CryptoJS.lib.WordArray.random(16);
                cfg.iv = ivRand;
                usedIvHex = CryptoJS.enc.Hex.stringify(ivRand);
            }

            const encrypted = CryptoJS.AES.encrypt(text, keyWords, cfg);
            const cipherB64 = encrypted.toString();
            // Вернём ivHex:base64, если IV был сгенерирован автоматически
            if (usedIvHex) return `${usedIvHex}:${cipherB64}`;
            return cipherB64;
        },
        decode: (cipher, opts) => {
            const { key, iv } = opts;
            if (!key) throw new Error("Укажите ключ");

            let keyWords;
            if (/^[0-9a-fA-F]+$/.test(key)) {
                if (![32, 48, 64].includes(key.length)) {
                    throw new Error(
                        "Длина hex-ключа должна быть 32/48/64 символа (16/24/32 байта)",
                    );
                }
                keyWords = CryptoJS.enc.Hex.parse(key);
            } else {
                keyWords = CryptoJS.SHA256(key);
            }

            const cfg = {
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7,
            };
            let cipherText = cipher.trim();

            if (iv && iv.trim()) {
                const ivStr = iv.trim();
                if (!/^[0-9a-fA-F]+$/.test(ivStr) || ivStr.length % 2 !== 0) {
                    throw new Error("IV должен быть hex-строкой чётной длины");
                }
                cfg.iv = CryptoJS.enc.Hex.parse(ivStr);
            } else {
                // Попробуем извлечь IV из шифртекста формата ivHex:Base64
                const m = cipherText.match(
                    /^([0-9a-fA-F]+):([A-Za-z0-9+/=]+)$/,
                );
                if (m) {
                    const ivHex = m[1];
                    const data = m[2];
                    if (ivHex.length % 2 !== 0) {
                        throw new Error(
                            "IV в шифртексте должен иметь чётную длину",
                        );
                    }
                    cfg.iv = CryptoJS.enc.Hex.parse(ivHex);
                    cipherText = data;
                } else {
                    throw new Error(
                        "Укажите IV (hex) или вставьте шифртекст в формате ivHex:Base64",
                    );
                }
            }

            const decrypted = CryptoJS.AES.decrypt(cipherText, keyWords, cfg);
            return CryptoJS.enc.Utf8.stringify(decrypted);
        },
    },
    rsa: {
        title: "RSA",
        desc: "Асимметричное шифрование RSA (RSA-OAEP, SHA-256). Для шифрования используйте публичный ключ (PEM), для дешифрования — приватный (PEM).",
        allowDecode: true,
        buildOptions: (mode) => {
            return [
                {
                    id: mode === "encode" ? "publicKey" : "privateKey",
                    label:
                        mode === "encode"
                            ? "Публичный ключ (PEM)"
                            : "Приватный ключ (PEM)",
                    type: "textarea",
                    placeholder:
                        "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
                },
            ];
        },
        encode: async (text, opts) => {
            const { publicKey } = opts;
            if (!publicKey) throw new Error("Укажите публичный ключ");

            let keyData;
            const trimmed = publicKey.trim();
            if (trimmed.startsWith("ssh-ed25519")) {
                throw new Error(
                    "ssh-ed25519 — это ключ Ed25519 для подписи/аутентификации, не подходит для RSA шифрования. Используйте RSA публичный ключ (PEM) или OpenSSH формат ssh-rsa.",
                );
            } else if (trimmed.startsWith("ssh-rsa ")) {
                keyData = openSshRsaToSpki(trimmed);
            } else {
                keyData = pemToBinary(publicKey, "PUBLIC KEY");
            }

            const cryptoKey = await window.crypto.subtle.importKey(
                "spki",
                keyData,
                { name: "RSA-OAEP", hash: "SHA-256" },
                false,
                ["encrypt"],
            );
            const data = new TextEncoder().encode(text);
            const encrypted = await window.crypto.subtle.encrypt(
                { name: "RSA-OAEP" },
                cryptoKey,
                data,
            );
            return arrayBufferToBase64(encrypted);
        },
        decode: async (cipher, opts) => {
            const { privateKey } = opts;
            if (!privateKey) throw new Error("Укажите приватный ключ");

            const trimmed = privateKey.trim();
            let keyData;
            if (trimmed.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----")) {
                // OpenSSH (не зашифрованный) -> PKCS#8
                keyData = opensshPrivateToPkcs8(trimmed);
            } else if (trimmed.includes("BEGIN RSA PRIVATE KEY")) {
                // PKCS#1 -> PKCS#8
                const pkcs1 = pemToBinary(privateKey, "RSA PRIVATE KEY");
                keyData = pkcs1ToPkcs8(pkcs1);
            } else {
                // PKCS#8
                keyData = pemToBinary(privateKey, "PRIVATE KEY");
            }

            const cryptoKey = await window.crypto.subtle.importKey(
                "pkcs8",
                keyData,
                { name: "RSA-OAEP", hash: "SHA-256" },
                false,
                ["decrypt"],
            );
            const encData = base64ToArrayBuffer(cipher.trim());
            const decrypted = await window.crypto.subtle.decrypt(
                { name: "RSA-OAEP" },
                cryptoKey,
                encData,
            );
            return new TextDecoder().decode(decrypted);
        },
    },
};

var url = window.location.href;
let normalizedUrl = url.substring(url.lastIndexOf("?") + 1);
const urlParams = new URLSearchParams(normalizedUrl);
const params = Object.fromEntries(urlParams.entries());

let currentTool = params.crypto;
const optionsContainer = document.getElementById("options");

function field(title, id, ctrl, helper) {
    const wrapper = document.createElement("div");
    wrapper.className = "panel__option";
    const label = document.createElement("label");
    label.textContent = title;
    label.htmlFor = id;
    ctrl.id = id;
    wrapper.appendChild(label);
    wrapper.appendChild(ctrl);
    if (helper) {
        const help = document.createElement("div");
        help.className = "helper";
        help.textContent = helper;
        wrapper.appendChild(help);
    }
    return wrapper;
}

function setPlaceholdersByTool(toolKey, mode) {
    if (toolKey === "aes") {
        input.placeholder =
            mode === "encode"
                ? "Введите открытый текст. Результат будет Base64 шифртекст (если IV не указан — вернётся ivHex:Base64)."
                : "Вставьте Base64 шифртекст или строку формата ivHex:Base64.";
        output.placeholder =
            mode === "encode"
                ? "Здесь появится Base64 шифртекст (или ivHex:Base64)."
                : "Здесь появится расшифрованный текст.";
    } else if (toolKey === "rsa") {
        input.placeholder =
            mode === "encode"
                ? "Введите открытый текст. Результат — Base64."
                : "Вставьте Base64 шифртекст для расшифровки.";
        output.placeholder =
            mode === "encode"
                ? "Здесь появится Base64 шифртекст."
                : "Здесь появится расшифрованный текст.";
    } else {
        // defaults
        input.placeholder = "Введите текст для кодирования...";
        output.placeholder = "Результат появится здесь...";
    }
}

function renderOptions() {
    const tool = tools[currentTool];
    const mode = [...modeInputs].find((i) => i.checked).value;
    const fields =
        typeof tool.buildOptions === "function" ? tool.buildOptions(mode) : [];
    optionsContainer.innerHTML = "";

    // build custom fields with helpers for AES / RSA
    if (currentTool === "aes") {
        const key = document.createElement("input");
        key.type = "text";
        key.placeholder =
            "Пример: mySecretKey или 603deb1015ca71be2b73aef0857d7781";
        optionsContainer.appendChild(
            field(
                "Ключ (строка или hex)",
                "key",
                key,
                "Можно ввести обычную строку (UTF-8) или hex-ключ (128/192/256 бит).",
            ),
        );

        const iv = document.createElement("input");
        iv.type = "text";
        iv.placeholder = "Пример: 000102030405060708090a0b0c0d0e0f";
        optionsContainer.appendChild(
            field(
                "IV (hex, необязательно)",
                "iv",
                iv,
                "Используется в режиме CBC. Обычно 16 байт (32 hex-символа).",
            ),
        );
    } else if (currentTool === "rsa") {
        const isEncode = mode === "encode";
        const ta = document.createElement("textarea");
        ta.rows = 7;
        ta.placeholder = isEncode
            ? "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqh...\n-----END PUBLIC KEY-----"
            : "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg...\n-----END PRIVATE KEY-----";
        optionsContainer.appendChild(
            field(
                isEncode
                    ? "Публичный ключ (PEM/ssh-rsa)"
                    : "Приватный ключ (PEM/OpenSSH)",
                isEncode ? "publicKey" : "privateKey",
                ta,
                isEncode
                    ? "Поддерживаемый формат публичного ключа: PEM (-----BEGIN PUBLIC KEY-----, SPKI) или OpenSSH ssh-rsa AAAA...."
                    : "Поддерживаемые форматы: PKCS#8 (-----BEGIN PRIVATE KEY-----), PKCS#1 (-----BEGIN RSA PRIVATE KEY-----) или незашифрованный OpenSSH (-----BEGIN OPENSSH PRIVATE KEY-----).",
            ),
        );
    } else {
        // generic fields (if any)
        fields.forEach((f) => {
            let ctrl;
            if (f.type === "textarea") {
                ctrl = document.createElement("textarea");
                ctrl.rows = 5;
            } else {
                ctrl = document.createElement("input");
                ctrl.type = f.type || "text";
            }
            if (f.placeholder) ctrl.placeholder = f.placeholder;
            optionsContainer.appendChild(field(f.label, f.id, ctrl));
        });
    }

    setPlaceholdersByTool(currentTool, mode);
}

menuItems.forEach((item) => {
    if (item.dataset.type === currentTool) {
        item.classList.add("active");

        currentTool = item.dataset.type;
        const tool = tools[currentTool];

        title.textContent = tool.title;
        desc.textContent = tool.desc;

        input.value = "";
        output.value = "";

        modeInputs.forEach((i) => {
            if (i.value === "decode") {
                i.disabled = !tool.allowDecode;
                if (!tool.allowDecode) i.checked = false;
            }

            if (i.value === params.mode) {
                i.checked = true;
            }
        });

        renderOptions();
    }
});

// ===== MENU SWITCH =====
menuItems.forEach((item) => {
    item.addEventListener("click", () => {
        menuItems.forEach((btn) => btn.classList.remove("active"));
        item.classList.add("active");

        currentTool = item.dataset.type;
        const tool = tools[currentTool];

        title.textContent = tool.title;
        desc.textContent = tool.desc;

        input.value = "";
        output.value = "";

        modeInputs.forEach((i) => {
            if (i.value === "decode") {
                i.disabled = !tool.allowDecode;
                if (!tool.allowDecode) i.checked = false;
            }
        });

        renderOptions();
    });
});

// ===== MODE CHANGE (options re-render) =====
modeInputs.forEach((i) => i.addEventListener("change", renderOptions));

// ===== UTILS (RSA/WebCrypto) =====
function pemToBinary(pem, label) {
    const re = new RegExp(
        `-----BEGIN ${label}-----([\\s\\S]*?)-----END ${label}-----`,
    );
    const m = pem.replace(/\r/g, "").match(re);
    if (!m) throw new Error(`Некорректный PEM: отсутствует блок ${label}`);
    const b64 = m[1].replace(/\s+/g, "");
    return base64ToArrayBuffer(b64);
}
function base64ToArrayBuffer(b64) {
    const bin = atob(b64);
    const len = bin.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
}
function arrayBufferToBase64(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
}

// Convert OpenSSH 'ssh-rsa AAAA...' to SPKI (DER) ArrayBuffer
function openSshRsaToSpki(openSsh) {
    const parts = openSsh.trim().split(/\s+/);
    if (parts.length < 2 || parts[0] !== "ssh-rsa")
        throw new Error("Некорректный ssh-rsa ключ");
    const raw = base64ToArrayBuffer(parts[1]);
    const view = new DataView(raw);
    let off = 0;
    function readUint32() {
        const v = view.getUint32(off);
        off += 4;
        return v;
    }
    function readBuf() {
        const len = readUint32();
        const b = new Uint8Array(raw, off, len);
        off += len;
        return new Uint8Array(b);
    }
    function readStr() {
        const b = readBuf();
        return String.fromCharCode.apply(null, b);
    }
    const type = readStr();
    if (type !== "ssh-rsa") throw new Error("Ожидался тип ssh-rsa");
    const e = readBuf();
    const n = readBuf();

    // DER helpers
    function derLen(len) {
        if (len < 0x80) return new Uint8Array([len]);
        const bytes = [];
        let v = len;
        while (v > 0) {
            bytes.unshift(v & 0xff);
            v >>= 8;
        }
        return new Uint8Array([0x80 | bytes.length, ...bytes]);
    }
    function derInt(bytes) {
        let i = 0;
        while (i < bytes.length - 1 && bytes[i] === 0) i++;
        let body = bytes.slice(i);
        if (body[0] & 0x80) body = Uint8Array.from([0x00, ...body]);
        return concat(Uint8Array.from([0x02]), derLen(body.length), body);
    }
    function derSeq(...chunks) {
        const body = concat(...chunks);
        return concat(Uint8Array.from([0x30]), derLen(body.length), body);
    }
    function derBitString(bytes) {
        const padBits = Uint8Array.from([0x00]);
        const body = concat(padBits, bytes);
        return concat(Uint8Array.from([0x03]), derLen(body.length), body);
    }
    function derNull() { return Uint8Array.from([0x05, 0x00]); }
    function derOidRsaEncryption() { return Uint8Array.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]); }
    function concat(...arrs) {
        const total = arrs.reduce((s, a) => s + a.length, 0);
        const out = new Uint8Array(total);
        let p = 0;
        for (const a of arrs) { out.set(a, p); p += a.length; }
        return out;
    }

    const rsaPubKey = derSeq(derInt(n), derInt(e));
    const algId = derSeq(derOidRsaEncryption(), derNull());
    const spki = derSeq(algId, derBitString(rsaPubKey));
    return spki.buffer;
}

// Convert PKCS#1 RSAPrivateKey (DER) to PKCS#8 PrivateKeyInfo (DER)
function pkcs1ToPkcs8(pkcs1Der) {
    const pkcs1 = new Uint8Array(pkcs1Der);
    function derLen(len) { if (len < 0x80) return new Uint8Array([len]); const bytes=[]; let v=len; while(v>0){bytes.unshift(v&0xff); v>>=8;} return new Uint8Array([0x80|bytes.length, ...bytes]); }
    function derSeq(...chunks){ const body=concat(...chunks); return concat(Uint8Array.from([0x30]), derLen(body.length), body); }
    function derNull(){ return Uint8Array.from([0x05,0x00]); }
    function derOidRsaEncryption(){ return Uint8Array.from([0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01]); }
    function derOctetString(bytes){ return concat(Uint8Array.from([0x04]), derLen(bytes.length), bytes); }
    function concat(...arrs){ const total=arrs.reduce((s,a)=>s+a.length,0); const out=new Uint8Array(total); let p=0; for(const a of arrs){ out.set(a,p); p+=a.length; } return out; }
    const version = Uint8Array.from([0x02,0x01,0x00]);
    const algId = derSeq(derOidRsaEncryption(), derNull());
    const privKey = derOctetString(pkcs1);
    const pkcs8 = derSeq(version, algId, privKey);
    return pkcs8.buffer;
}

// Parse OpenSSH unencrypted RSA private key and return PKCS#8 DER ArrayBuffer
function opensshPrivateToPkcs8(pem) {
    const re = /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)-----END OPENSSH PRIVATE KEY-----/;
    const m = pem.replace(/\r/g,'').match(re);
    if (!m) throw new Error('Некорректный OpenSSH приватный ключ');
    const raw = base64ToArrayBuffer(m[1].replace(/\s+/g,''));
    const u8 = new Uint8Array(raw);
    const headerStr = 'openssh-key-v1\x00';
    for (let i=0;i<headerStr.length;i++){ if (u8[i] !== headerStr.charCodeAt(i)) throw new Error('Неподдерживаемый формат OpenSSH ключа'); }
    let off = headerStr.length;
    const view = new DataView(raw);
    function readUint32() { const v = view.getUint32(off); off += 4; return v; }
    function readBytes(len){ const b = u8.slice(off, off+len); off += len; return b; }
    function readString(){ const len = readUint32(); return readBytes(len); }
    function toAscii(bytes){ return String.fromCharCode.apply(null, Array.from(bytes)); }

    const ciphername = toAscii(readString());
    const kdfname = toAscii(readString());
    const kdfopts = readString();
    const nkeys = readUint32();
    for (let i=0;i<nkeys;i++) { /* skip pubkeys */ readString(); }
    const privBlob = readString();

    if (ciphername !== 'none' || kdfname !== 'none') {
        throw new Error('Этот OpenSSH приватный ключ зашифрован. Снимите пароль или конвертируйте в PKCS#8');
    }

    const dv = new DataView(privBlob.buffer, privBlob.byteOffset, privBlob.byteLength);
    let pOff = 0;
    function pReadUint32(){ const v = dv.getUint32(pOff); pOff += 4; return v; }
    function pReadBytes(len){ const b = privBlob.slice(pOff, pOff+len); pOff += len; return b; }
    function pReadString(){ const len = pReadUint32(); return pReadBytes(len); }

    const check1 = pReadUint32();
    const check2 = pReadUint32();
    const keytype = toAscii(pReadString());
    if (keytype !== 'ssh-rsa') throw new Error('В OpenSSH ключе ожидается тип ssh-rsa');

    function pReadMpint(){ const len = pReadUint32(); return pReadBytes(len); }

    const n = pReadMpint();
    const e = pReadMpint();
    const d = pReadMpint();
    const iqmp = pReadMpint();
    const p = pReadMpint();
    const q = pReadMpint();
    const _comment = pReadString();

    function bytesToBigInt(bytes){ let v=0n; for (const bb of bytes) { v = (v<<8n) + BigInt(bb); } return v; }
    function bigIntToBytes(v){ if (v===0n) return Uint8Array.of(0); const arr=[]; while(v>0n){ arr.push(Number(v & 0xffn)); v >>= 8n; } arr.reverse(); return Uint8Array.from(arr); }

    const nBI = bytesToBigInt(n);
    const eBI = bytesToBigInt(e);
    const dBI = bytesToBigInt(d);
    const pBI = bytesToBigInt(p);
    const qBI = bytesToBigInt(q);
    const dmp1BI = dBI % (pBI - 1n);
    const dmq1BI = dBI % (qBI - 1n);
    const iqmpBI = bytesToBigInt(iqmp);

    function derLen(len) { if (len < 0x80) return new Uint8Array([len]); const bytes=[]; let v=len; while(v>0){bytes.unshift(v&0xff); v>>=8;} return new Uint8Array([0x80|bytes.length, ...bytes]); }
    function concat(...arrs){ const total=arrs.reduce((s,a)=>s+a.length,0); const out=new Uint8Array(total); let p=0; for(const a of arrs){ out.set(a,p); p+=a.length; } return out; }
    function derIntFromBigInt(bi){ let bytes = bigIntToBytes(bi); if (bytes[0] & 0x80) bytes = Uint8Array.from([0x00, ...bytes]); return concat(Uint8Array.from([0x02]), derLen(bytes.length), bytes); }
    function derSeq(...chunks){ const body=concat(...chunks); return concat(Uint8Array.from([0x30]), derLen(body.length), body); }
    function derNull(){ return Uint8Array.from([0x05,0x00]); }
    function derOidRsaEncryption(){ return Uint8Array.from([0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01]); }
    function derOctetString(bytes){ return concat(Uint8Array.from([0x04]), derLen(bytes.length), bytes); }

    const version0 = Uint8Array.from([0x02,0x01,0x00]);
    const pkcs1 = derSeq(
        version0,
        derIntFromBigInt(nBI),
        derIntFromBigInt(eBI),
        derIntFromBigInt(dBI),
        derIntFromBigInt(pBI),
        derIntFromBigInt(qBI),
        derIntFromBigInt(dmp1BI),
        derIntFromBigInt(dmq1BI),
        derIntFromBigInt(iqmpBI)
    );

    const version = Uint8Array.from([0x02,0x01,0x00]);
    const algId = derSeq(derOidRsaEncryption(), derNull());
    const privKey = derOctetString(pkcs1);
    const pkcs8 = derSeq(version, algId, privKey);
    return pkcs8.buffer;
}

// ===== ACTION =====
actionBtn.addEventListener("click", async () => {
    if (!input.value) return;

    const tool = tools[currentTool];
    const mode = [...modeInputs].find((i) => i.checked).value;

    // собрать options
    const opts = {};
    const optControls = optionsContainer.querySelectorAll("input, textarea");
    optControls.forEach((c) => {
        opts[c.id] = c.value;
    });

    try {
        const res =
            mode === "encode"
                ? tool.encode(input.value, opts)
                : tool.decode(input.value, opts);
        output.value = res instanceof Promise ? await res : res;
    } catch (e) {
        console.error(e);
        output.value = e && e.message ? e.message : "Ошибка преобразования";
    }
});

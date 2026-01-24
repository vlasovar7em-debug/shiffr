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

    for (const w of words) {
        const hmd5 = CryptoJS.MD5(w).toString().toLowerCase();
        const hsha1 = CryptoJS.SHA1(w).toString().toLowerCase();
        // Сохраняем первый попавшийся (чтобы не перезаписывать при коллизиях)
        if (!md5Map[hmd5]) md5Map[hmd5] = w;
        if (!sha1Map[hsha1]) sha1Map[hsha1] = w;
    }

    wordlistLoaded = true;
    console.log("Словари хешей готовы:", {
        md5: Object.keys(md5Map).length,
        sha1: Object.keys(sha1Map).length,
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
    },
    md5: {
        title: "MD5",
        desc: "Хеширование текста с помощью MD5. Декодирование — поиск по словарю частых строк.",
        encode: (text) => CryptoJS.MD5(text).toString(),
        decode: (hash) => {
            if (!hash) return "Пустой хеш";
            const h = hash.trim().toLowerCase();
            if (!wordlistLoaded) {
                // Если словарь ещё не загружен, можно подождать или сказать пользователю.
                // Здесь используем уже подготовленный (встроенный) запас, т.к. он уже загружен синхронно.
                // Но если вы хотите ждать, можно вернуть специальное сообщение.
                console.warn(
                    "Словарь ещё загружается, поиск будет произведён по доступным данным.",
                );
            }
            if (md5Map[h]) return md5Map[h];
            return "Не удалось декодировать (не найдено в словаре)";
        },
        allowDecode: true,
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
    },
};

var url = window.location.href;
let normalizedUrl = url.substring(url.lastIndexOf("?") + 1);
const urlParams = new URLSearchParams(normalizedUrl);
const params = Object.fromEntries(urlParams.entries());

let currentTool = params.crypto;
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
    });
});

// ===== ACTION =====
actionBtn.addEventListener("click", () => {
    if (!input.value) return;

    const tool = tools[currentTool];
    const mode = [...modeInputs].find((i) => i.checked).value;

    try {
        output.value =
            mode === "encode"
                ? tool.encode(input.value)
                : tool.decode(input.value);
    } catch {
        output.value = "Ошибка преобразования";
    }
});

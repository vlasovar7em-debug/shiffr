// ===== ELEMENTS =====
const menuItems = document.querySelectorAll(".menu__item");
const title = document.getElementById("tool-title");
const desc = document.getElementById("tool-desc");

const input = document.getElementById("input");
const output = document.getElementById("output");
const actionBtn = document.getElementById("action-btn");

const modeInputs = document.querySelectorAll("input[name='mode']");

// ===== TOOL CONFIG =====
const tools = {
    base64: {
        title: "Base 64",
        desc: "Кодирование и декодирование текста в Base64",
        encode: text => btoa(unescape(encodeURIComponent(text))),
        decode: text => decodeURIComponent(escape(atob(text))),
        allowDecode: true
    },
    md5: {
        title: "MD5",
        desc: "Хеширование текста с помощью MD5",
        encode: text => CryptoJS.MD5(text).toString(),
        allowDecode: false
    },
    sha1: {
        title: "SHA1",
        desc: "Хеширование текста с помощью SHA1",
        encode: text => CryptoJS.SHA1(text).toString(),
        allowDecode: false
    }
};

let currentTool = "base64";

// ===== MENU SWITCH =====
menuItems.forEach(item => {
    item.addEventListener("click", () => {

        menuItems.forEach(btn => btn.classList.remove("active"));
        item.classList.add("active");

        currentTool = item.dataset.type;
        const tool = tools[currentTool];

        title.textContent = tool.title;
        desc.textContent = tool.desc;

        input.value = "";
        output.value = "";

        modeInputs.forEach(i => {
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
    const mode = [...modeInputs].find(i => i.checked).value;

    try {
        output.value =
            mode === "encode"
                ? tool.encode(input.value)
                : tool.decode(input.value);
    } catch {
        output.value = "Ошибка преобразования";
    }
});
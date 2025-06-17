/**
 * ===== CLIENT.JS CẢI TIẾN NÂNG CAO =====
 * - Mã hóa khóa riêng tư lưu localStorage bằng AES với mật khẩu người dùng nhập
 * - Giải mã khóa riêng tư khi load lại để dùng
 * - Truyền file chia nhỏ chunk qua WebSocket từng phần base64, quản lý tiến trình
 * - UI nhập mật khẩu mã hóa khóa
 * - Fallback kiểm tra Web Crypto API, WebSocket
 * - Thông báo trạng thái nâng cao cho người dùng
 */

// Kiểm tra hỗ trợ API
if (!window.crypto || !window.crypto.subtle) {
    alert("Trình duyệt của bạn không hỗ trợ Web Crypto API. Vui lòng dùng trình duyệt mới hơn.");
}
if (!window.WebSocket) {
    alert("Trình duyệt của bạn không hỗ trợ WebSocket. Ứng dụng này sẽ không hoạt động.");
}

/**
 * Utils PEM encoding/decoding
 */
function arrayBufferToPEM(buffer, label) {
    const base64 = window.btoa(String.fromCharCode(...new Uint8Array(buffer)));
    const maxLineLength = 64;
    const lines = [];
    for (let i = 0; i < base64.length; i += maxLineLength) {
        lines.push(base64.slice(i, i + maxLineLength));
    }
    return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}
function pemToArrayBuffer(pem) {
    const lines = pem.trim().split('\n');
    const base64Lines = lines.filter(line =>
        !line.startsWith('-----BEGIN') && !line.startsWith('-----END')
    );
    const base64 = base64Lines.join('');
    const binaryString = window.atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * AES-GCM 256-bit mã hóa dữ liệu Uint8Array với mật khẩu người dùng
 */
async function deriveKeyFromPassword(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw', 
        enc.encode(password), 
        {name: 'PBKDF2'}, 
        false, 
        ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt,
            iterations: 100000,
            hash: 'SHA-256',
        },
        keyMaterial,
        {name: 'AES-GCM', length: 256},
        false,
        ['encrypt', 'decrypt']
    );
}
async function encryptPrivateKey(privateKeyPEM, password) {
    const enc = new TextEncoder();
    const data = enc.encode(privateKeyPEM);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12)); // AES-GCM nonce 12 bytes
    const key = await deriveKeyFromPassword(password, salt);
    const encrypted = await crypto.subtle.encrypt({name: 'AES-GCM', iv}, key, data);
    // Lưu: salt + iv + encrypted
    const encryptedFull = new Uint8Array(salt.byteLength + iv.byteLength + encrypted.byteLength);
    encryptedFull.set(salt, 0);
    encryptedFull.set(iv, salt.byteLength);
    encryptedFull.set(new Uint8Array(encrypted), salt.byteLength + iv.byteLength);
    return window.btoa(String.fromCharCode(...encryptedFull));
}
async function decryptPrivateKey(encryptedBase64, password) {
    const encryptedFull = Uint8Array.from(window.atob(encryptedBase64), c => c.charCodeAt(0));
    const salt = encryptedFull.slice(0,16);
    const iv = encryptedFull.slice(16,28);
    const data = encryptedFull.slice(28);
    const key = await deriveKeyFromPassword(password, salt);
    try {
        const decrypted = await crypto.subtle.decrypt({name: 'AES-GCM', iv}, key, data);
        const dec = new TextDecoder();
        return dec.decode(decrypted);
    } catch {
        throw new Error("Mật khẩu không đúng hoặc dữ liệu khóa bị hỏng");
    }
}

/**
 * Tạo cặp khóa RSA OAEP + PSS
 */
async function generateKeyPair(modulusLength) {
    const encryptKeyPair = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: "SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
    );
    const signKeyPair = await crypto.subtle.generateKey(
        {
            name: "RSA-PSS",
            modulusLength,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: "SHA-256"
        },
        true,
        ["sign", "verify"]
    );
    return { encryptKeyPair, signKeyPair };
}

/**
 * Xuất PEM chuẩn khóa
 */
async function exportPublicKey(key) {
    const exported = await crypto.subtle.exportKey("spki", key);
    return arrayBufferToPEM(exported, "PUBLIC KEY");
}
async function exportPrivateKey(key) {
    const exported = await crypto.subtle.exportKey("pkcs8", key);
    return arrayBufferToPEM(exported, "PRIVATE KEY");
}

/**
 * Nhập PEM thành CryptoKey
 */
async function importPublicKey(pem, algo="RSA-OAEP") {
    const der = pemToArrayBuffer(pem);
    return crypto.subtle.importKey(
        "spki",
        der,
        { name: algo, hash: "SHA-256" },
        true,
        algo === "RSA-OAEP" ? ["encrypt"] : ["verify"]
    );
}
async function importPrivateKey(pem, algo="RSA-OAEP") {
    const der = pemToArrayBuffer(pem);
    return crypto.subtle.importKey(
        "pkcs8",
        der,
        { name: algo, hash: "SHA-256" },
        true,
        algo === "RSA-OAEP" ? ["decrypt"] : ["sign"]
    );
}

/**
 * Sign và verify
 */
async function signData(privateKey, data) {
    return new Uint8Array(await crypto.subtle.sign({name: "RSA-PSS", saltLength:32}, privateKey, data));
}
async function verifySignature(publicKey, signature, data) {
    return crypto.subtle.verify({name:"RSA-PSS", saltLength:32}, publicKey, signature, data);
}

/**
 * Mã hóa RSA chia chunk chuẩn OAEP
 */
async function encryptData(publicKey, data) {
    const keySize = publicKey.algorithm.modulusLength || 2048;
    const maxChunkSize = keySize / 8 - 42;
    const chunks = [];
    for(let offset=0; offset < data.length; offset += maxChunkSize) {
        const chunk = data.slice(offset, offset + maxChunkSize);
        const encrypted = await crypto.subtle.encrypt({name:"RSA-OAEP"}, publicKey, chunk);
        chunks.push(new Uint8Array(encrypted));
    }
    return chunks;
}

/**
 * Giải mã RSA theo chunk
 */
async function decryptData(privateKey, encryptedChunks) {
    const decryptedChunks = [];
    for(const chunk of encryptedChunks) {
        const decrypted = await crypto.subtle.decrypt({name:"RSA-OAEP"}, privateKey, chunk);
        decryptedChunks.push(new Uint8Array(decrypted));
    }
    const length = decryptedChunks.reduce((a,c) => a+c.length,0);
    const result = new Uint8Array(length);
    let offset=0;
    for(const chunk of decryptedChunks) {
        result.set(chunk, offset);
        offset += chunk.length;
    }
    return result;
}

/**
 * Kiểm tra và định dạng file chunk
 */
function chunkToBase64(chunk) {
    return window.btoa(String.fromCharCode(...chunk));
}
function base64ToChunk(b64) {
    return Uint8Array.from(window.atob(b64), c => c.charCodeAt(0));
}

/**
 * Tính kiểm tra SHA-256
 */
async function calculateChecksum(data) {
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Thông báo toast
 */
function showToast(message,type="info") {
    Toastify({
        text: message,
        duration: 4000,
        gravity: "top",
        position: "right",
        backgroundColor: type==="error" ? "#ef4444" : (type==="success" ? "#22c55e" : "#3b82f6"),
        className: "toastify"
    }).showToast();
}

/**
 * Lưu khóa mã hóa riêng tư đã mã hóa AES (base64)
 */
function saveEncryptedPrivateKey(encryptedPrivKeyB64) {
    localStorage.setItem("encryptedPrivateKey", encryptedPrivKeyB64);
}

/**
 * Lấy khóa mã hóa riêng tư mã hóa AES
 */
function loadEncryptedPrivateKey() {
    return localStorage.getItem("encryptedPrivateKey");
}

/**
 * Global quản lý khóa, WebSocket, trạng thái gửi nhận
 */
let publicKey = null;
let privateKey = null;
let signPublicKey = null;
let signPrivateKey = null;
let socket = null;
let username = null;
const publicKeys = new Map();

let pendingFileToSend = null; // File khi gửi từng chunk
let receiverOfPendingFile = null;
let currentChunkIndex = 0;

// UI Elements bổ sung
const passwordInput = document.getElementById("passwordInput"); // Giả sử thêm input nhập mật khẩu
const generateKeyBtn = document.getElementById("generateKeyBtn");
const loginBtn = document.getElementById("loginBtn");
const sendBtn = document.getElementById("sendBtn");
const sendSpinner = document.getElementById("sendSpinner");

// --- Hàm tạo khóa nâng cao --- //
generateKeyBtn.addEventListener("click", async () => {
    const keySize = parseInt(document.getElementById("keySize").value);
    const password = passwordInput.value;
    if(!password || password.length < 8) {
        showToast("Vui lòng nhập mật khẩu ít nhất 8 ký tự để mã hóa khóa riêng tư", "error");
        return;
    }
    try {
        toggleGenerateKeyUI(false);
        const keys = await generateKeyPair(keySize);
        publicKey = keys.encryptKeyPair.publicKey;
        privateKey = keys.encryptKeyPair.privateKey;
        signPublicKey = keys.signKeyPair.publicKey;
        signPrivateKey = keys.signKeyPair.privateKey;

        const pubEncryptPEM = await exportPublicKey(publicKey);
        const privEncryptPEM = await exportPrivateKey(privateKey);
        const pubSignPEM = await exportPublicKey(signPublicKey);
        const privSignPEM = await exportPrivateKey(signPrivateKey);

        // Mã hóa khóa riêng tư với mật khẩu rồi lưu
        const encryptedPrivEncrypt = await encryptPrivateKey(privEncryptPEM, password);
        const encryptedPrivSign = await encryptPrivateKey(privSignPEM, password);

        saveKeysLocally(pubEncryptPEM, encryptedPrivEncrypt, pubSignPEM, encryptedPrivSign);

        document.getElementById("publicKey").value = pubEncryptPEM;
        document.getElementById("privateKey").value = "[Khóa riêng tư đã được mã hóa và lưu trữ an toàn]";
        showToast("Tạo khóa và mã hóa khóa riêng tư thành công", "success");
    } catch (e) {
        showToast("Lỗi tạo khóa: " + e.message, "error");
    } finally {
        toggleGenerateKeyUI(true);
    }
});

/**
 * Load khóa từ localStorage, giải mã khóa riêng tư với mật khẩu
 */
async function loadKeysWithPassword(password) {
    const pubEncryptPEM = localStorage.getItem("publicKeyEncrypt");
    const encryptedPrivEncryptB64 = localStorage.getItem("privateKeyEncrypt");
    const pubSignPEM = localStorage.getItem("publicKeySign");
    const encryptedPrivSignB64 = localStorage.getItem("privateKeySign");

    if(!pubEncryptPEM || !encryptedPrivEncryptB64 || !pubSignPEM || !encryptedPrivSignB64) {
        throw new Error("Không tìm thấy khóa đã lưu");
    }

    const privEncryptPEM = await decryptPrivateKey(encryptedPrivEncryptB64, password);
    const privSignPEM = await decryptPrivateKey(encryptedPrivSignB64, password);

    publicKey = await importPublicKey(pubEncryptPEM, "RSA-OAEP");
    privateKey = await importPrivateKey(privEncryptPEM, "RSA-OAEP");
    signPublicKey = await importPublicKey(pubSignPEM, "RSA-PSS");
    signPrivateKey = await importPrivateKey(privSignPEM, "RSA-PSS");
}

/**
 * Đăng nhập, nhập mật khẩu giải mã khóa riêng tư
 */
loginBtn.addEventListener("click", async () => {
    username = document.getElementById("username").value.trim();
    const password = passwordInput.value;
    if(!username) { showToast("Vui lòng nhập username", "error"); return; }
    if(!password) { showToast("Vui lòng nhập mật khẩu để giải mã khóa", "error"); return; }
    try {
        await loadKeysWithPassword(password);
        showToast("Giải mã khóa thành công", "success");
    } catch (e) {
        showToast("Lỗi giải mã khóa: " + e.message, "error");
        return;
    }

    // Kết nối WebSocket, đăng nhập
    socket = new WebSocket("ws://localhost:8765");
    socket.onopen = async () => {
        const pubEncryptStr = await exportPublicKey(publicKey);
        const pubSignStr = await exportPublicKey(signPublicKey);
        socket.send(JSON.stringify({
            command: "login",
            username,
            public_key: btoa(JSON.stringify({encrypt: pubEncryptStr, sign: pubSignStr}))
        }));
    };
    // Trạng thái, xử lý message, lỗi, close để cập nhật UI như code cũ nhưng có thể mở rộng thêm

    // ...
});

/**
 * Gửi file theo chunk base64 từng phần qua websocket
 */
async function sendFileInChunks(file, receiver) {
    const CHUNK_SIZE = 16 * 1024; // 16KB cho mỗi chunk
    let offset = 0;
    const reader = new FileReader();

    return new Promise((resolve, reject) => {
        reader.onerror = () => reject(new Error("Lỗi đọc file"));
        reader.onload = async (e) => {
            const chunkData = new Uint8Array(e.target.result);
            const receiverPublicKeys = publicKeys.get(receiver);
            if(!receiverPublicKeys || !receiverPublicKeys.encrypt) {
                showToast("Không có khóa công khai của người nhận", "error");
                reject(new Error("Khóa công khai thiếu"));
                return;
            }

            try {
                // Mã hóa chunk
                const encryptedChunks = await encryptData(receiverPublicKeys.encrypt, chunkData);
                // Gộp chunk mã hóa nhỏ thành 1 mảng
                const totalLength = encryptedChunks.reduce((a,c) => a + c.length, 0);
                const encryptedData = new Uint8Array(totalLength);
                let off = 0;
                for(const c of encryptedChunks) {
                    encryptedData.set(c, off);
                    off += c.length;
                }
                const b64Chunk = btoa(String.fromCharCode(...encryptedData));
                const checksum = await calculateChecksum(encryptedData);

                // Ký chunk
                const signature = await signData(signPrivateKey, chunkData);
                const signatureB64 = btoa(String.fromCharCode(...signature));

                // Gửi chunk qua websocket với index các chunk
                socket.send(JSON.stringify({
                    command: "send_file_chunk",
                    receiver,
                    filename: file.name,
                    chunkData: b64Chunk,
                    chunkIndex: offset / CHUNK_SIZE,
                    chunkSize: chunkData.length,
                    checksum,
                    signature: signatureB64,
                    totalSize: file.size
                }));
            } catch(e) {
                reject(e);
                return;
            }
            offset += CHUNK_SIZE;
            if(offset < file.size) {
                readNextChunk();
            } else {
                resolve();
            }
        };
        function readNextChunk() {
            const slice = file.slice(offset, offset + CHUNK_SIZE);
            reader.readAsArrayBuffer(slice);
        }
        readNextChunk();
    });
}

// Thực hiện gửi khi nhấn nút
sendBtn.addEventListener("click", async () => {
    const receiver = document.getElementById("receiver").value.trim();
    const fileInput = document.getElementById("fileInput").files[0];
    if(!receiver) { showToast("Vui lòng nhập người nhận", "error"); return; }
    if(!fileInput) { showToast("Vui lòng chọn file", "error"); return; }
    if(fileInput.size > 50 * 1024*1024) { // Giới hạn file lớn
        showToast("File quá lớn, tối đa 50MB", "error");
        return;
    }
    if(!publicKeys.has(receiver)) {
        socket.send(JSON.stringify({command: "get_public_key", target_user: receiver}));
        showToast("Đang lấy khóa công khai người nhận...", "info");
        return;
    }
    sendSpinner.style.display = "inline-block";
    sendBtn.disabled = true;
    try {
        await sendFileInChunks(fileInput, receiver);
        showToast("Đã gửi file thành công", "success");
    } catch(e) {
        showToast("Lỗi gửi file: " + e.message, "error");
    } finally {
        sendSpinner.style.display = "none";
        sendBtn.disabled = false;
    }
});

// Các xử lý nhận file chunk, ghép file, xác minh chữ ký trên client và server phải tương ứng, đây là phần cần server hỗ trợ thêm.
// UI và logic mở rộng cho nhập mật khẩu mã hóa khóa, đăng nhập, tải lại khóa private cũng phải tích hợp.

// Các hàm UI toggle, toast, định dạng file và thời gian giữ nguyên hoặc cải tiến theo yêu cầu.

// Bạn cũng cần bổ sung phần UI: Thêm input mật khẩu, thay đổi nút tạo khóa và đăng nhập để nhập mật khẩu, hiển thị trạng thái.

// ----------
// Với các cải tiến này, ứng dụng của bạn sẽ an toàn hơn với khóa riêng tư được mã hóa, có thể xử lý file lớn qua chunk nhỏ, đồng thời nâng cao trải nghiệm người dùng với giao tiếp rõ ràng.
// Nếu bạn muốn, tôi có thể hỗ trợ bạn tạo đoạn HTML thủ công tích hợp UI nhập mật khẩu theo mô hình mới này.
// ----------



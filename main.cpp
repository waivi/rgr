#include <iostream>
#include <string>
#include <vector>
#include <limits>
#include <cstring>
#include <iomanip>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

// Типы для Полибия
using PolybiusFileFunc = bool (*)(const char*, const char*);
using PolybiusEncryptTextFunc = std::vector<unsigned char>* (*)(const char*);
using PolybiusDecryptTextFunc = char* (*)(const unsigned char*, size_t);
using FreeMemoryFunc = void (*)(void*);

// Типы для Атбаша
using AtbashTextFunc = char* (*)(const char*);
using AtbashFileFunc = void (*)(const char*, const char*); // Новый тип
using FreeMemoryAtbashFunc = void (*)(void*);

// Типы для RSA
using RsaGenerateKeysFunc = bool (*)(unsigned int, const char*, const char*);
using RsaFileFunc = bool (*)(const char*, const char*, const char*);
using RsaTextFunc = char* (*)(const char*, const char*);
using RsaFreeStringFunc = void (*)(char*);

void setup_windows_console() {
#ifdef _WIN32
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
#endif
}

void clear_cin() {
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

int get_menu_choice(int min, int max) {
    int choice;
    while (true) {
        std::cout << u8">> ";
        std::cin >> choice;
        if (!std::cin || choice < min || choice > max) {
            std::cout << u8"Ошибка: Пожалуйста, введите число между " << min << u8" и " << max << u8".\n";
            std::cin.clear();
            clear_cin();
        } else {
            clear_cin();
            return choice;
        }
    }
}

void run_polybius_menu() {
    void* handle = nullptr;
#ifdef _WIN32
    handle = LoadLibraryA("polybius.dll");
#else
    handle = dlopen("./libpolybius.so", RTLD_LAZY);
#endif
    if (!handle) { std::cerr << u8"Ошибка: Не удалось загрузить библиотеку Полибия.\n"; return; }
#ifdef _WIN32
    auto e_file = (PolybiusFileFunc)GetProcAddress((HMODULE)handle, "encrypt_file_polybius");
    auto d_file = (PolybiusFileFunc)GetProcAddress((HMODULE)handle, "decrypt_file_polybius");
    auto e_text = (PolybiusEncryptTextFunc)GetProcAddress((HMODULE)handle, "encrypt_text_polybius");
    auto d_text = (PolybiusDecryptTextFunc)GetProcAddress((HMODULE)handle, "decrypt_text_polybius");
    auto free_mem = (FreeMemoryFunc)GetProcAddress((HMODULE)handle, "free_memory");
    auto free_vec = (FreeMemoryFunc)GetProcAddress((HMODULE)handle, "free_vector");
#else
    auto e_file = (PolybiusFileFunc)dlsym(handle, "encrypt_file_polybius");
    auto d_file = (PolybiusFileFunc)dlsym(handle, "decrypt_file_polybius");
    auto e_text = (PolybiusEncryptTextFunc)dlsym(handle, "encrypt_text_polybius");
    auto d_text = (PolybiusDecryptTextFunc)dlsym(handle, "decrypt_text_polybius");
    auto free_mem = (FreeMemoryFunc)dlsym(handle, "free_memory");
    auto free_vec = (FreeMemoryFunc)dlsym(handle, "free_vector");
#endif
    if (!e_file || !d_file || !e_text || !d_text || !free_mem || !free_vec) {
        std::cerr << u8"Ошибка: Не удалось найти функции в библиотеке Полибия.\n";
    } else {
        std::cout << u8"\n--- Меню шифра Полибия ---\n";
        std::cout << u8"1. Зашифровать файл\n2. Расшифровать файл\n3. Зашифровать текст\n4. Расшифровать текст\n5. Назад\n";
        int choice = get_menu_choice(1, 5);
        if (choice != 5) {
            std::string in_path, out_path, text;
            if (choice == 1 || choice == 2) {
                std::cout << u8"Исходный файл: "; std::getline(std::cin, in_path);
                std::cout << u8"Целевой файл: "; std::getline(std::cin, out_path);
                bool success = (choice == 1) ? e_file(in_path.c_str(), out_path.c_str()) : d_file(in_path.c_str(), out_path.c_str());
                if (success) std::cout << u8"Операция завершена.\n";
                else std::cerr << u8"Ошибка при операции с файлом.\n";
            } else if (choice == 3) {
                std::cout << u8"Текст для шифрования: "; std::getline(std::cin, text);
                std::vector<unsigned char>* res_vec = e_text(text.c_str());
                std::cout << u8"Результат (hex): ";
                for (unsigned char c : *res_vec) std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c) << " ";
                std::cout << std::dec << std::endl;
                free_vec(res_vec);
            } else {
                std::cout << u8"Зашифрованный текст (hex): "; std::getline(std::cin, text);
                std::vector<unsigned char> data;
                std::stringstream ss(text);
                int byte;
                while (ss >> std::hex >> byte) data.push_back(static_cast<unsigned char>(byte));
                if (data.empty() && !text.empty()) {
                     std::cout << u8"Ошибка: Неверный hex формат.\n";
                } else {
                    char* res_str = d_text(data.data(), data.size());
                    std::cout << u8"Расшифрованный текст: " << res_str << std::endl;
                    free_mem(res_str);
                }
            }
        }
    }
#ifdef _WIN32
    FreeLibrary((HMODULE)handle);
#else
    dlclose(handle);
#endif
}

void run_atbash_menu() {
    void* handle = nullptr;
#ifdef _WIN32
    handle = LoadLibraryA("atbash.dll");
#else
    handle = dlopen("./libatbash.so", RTLD_LAZY);
#endif
    if (!handle) { std::cerr << u8"Ошибка: Не удалось загрузить библиотеку Атбаш.\n"; return; }
#ifdef _WIN32
    auto p_text = (AtbashTextFunc)GetProcAddress((HMODULE)handle, "process_text_atbash");
    auto p_file = (AtbashFileFunc)GetProcAddress((HMODULE)handle, "process_file_atbash");
    auto free_mem = (FreeMemoryAtbashFunc)GetProcAddress((HMODULE)handle, "free_memory_atbash");
#else
    auto p_text = (AtbashTextFunc)dlsym(handle, "process_text_atbash");
    auto p_file = (AtbashFileFunc)dlsym(handle, "process_file_atbash");
    auto free_mem = (FreeMemoryAtbashFunc)dlsym(handle, "free_memory_atbash");
#endif
    if (!p_text || !p_file || !free_mem) {
        std::cerr << u8"Ошибка: Не удалось найти функции в библиотеке Атбаш.\n";
    } else {
        std::cout << u8"\n--- Меню шифра Атбаш ---\n";
        std::cout << u8"Шифр Атбаш симметричен: шифрование и расшифрование - одна операция.\n";
        std::cout << u8"1. Обработать текст\n2. Обработать файл\n3. Назад\n";
        int choice = get_menu_choice(1, 3);
        if (choice == 1) {
            std::string text;
            std::cout << u8"Текст для обработки: "; std::getline(std::cin, text);
            char* result_str = p_text(text.c_str());
            std::cout << u8"Результат: " << result_str << std::endl;
            free_mem(result_str);
        } else if (choice == 2) {
            std::string in_path, out_path;
            std::cout << u8"Исходный файл: "; std::getline(std::cin, in_path);
            std::cout << u8"Целевой файл: "; std::getline(std::cin, out_path);
            p_file(in_path.c_str(), out_path.c_str());
            std::cout << u8"Файл успешно обработан.\n";
        }
    }
#ifdef _WIN32
    FreeLibrary((HMODULE)handle);
#else
    dlclose(handle);
#endif
}

void run_rsa_menu() {
    void* handle = nullptr;
#ifdef _WIN32
    handle = LoadLibraryA("rsa.dll");
#else
    handle = dlopen("./librsa.so", RTLD_LAZY);
#endif
    if (!handle) { std::cerr << u8"Ошибка: Не удалось загрузить библиотеку librsa.so.\n"; return; }
#ifdef _WIN32
    auto generate_keys = (RsaGenerateKeysFunc)GetProcAddress((HMODULE)handle, "generate_and_save_keys");
    auto encrypt_file = (RsaFileFunc)GetProcAddress((HMODULE)handle, "encrypt_file_wrapper");
    auto decrypt_file = (RsaFileFunc)GetProcAddress((HMODULE)handle, "decrypt_file_wrapper");
    auto encrypt_text = (RsaTextFunc)GetProcAddress((HMODULE)handle, "encrypt_text_wrapper");
    auto decrypt_text = (RsaTextFunc)GetProcAddress((HMODULE)handle, "decrypt_text_wrapper");
    auto free_string = (RsaFreeStringFunc)GetProcAddress((HMODULE)handle, "free_rsa_string");
#else
    auto generate_keys = (RsaGenerateKeysFunc)dlsym(handle, "generate_and_save_keys");
    auto encrypt_file = (RsaFileFunc)dlsym(handle, "encrypt_file_wrapper");
    auto decrypt_file = (RsaFileFunc)dlsym(handle, "decrypt_file_wrapper");
    auto encrypt_text = (RsaTextFunc)dlsym(handle, "encrypt_text_wrapper");
    auto decrypt_text = (RsaTextFunc)dlsym(handle, "decrypt_text_wrapper");
    auto free_string = (RsaFreeStringFunc)dlsym(handle, "free_rsa_string");
#endif

    if (!generate_keys || !encrypt_file || !decrypt_file || !encrypt_text || !decrypt_text || !free_string) {
        std::cerr << u8"Ошибка: Не удалось найти одну или несколько функций в библиотеке RSA.\n";
    } else {
        std::cout << u8"\n--- Меню RSA (на базе Boost, PKCS#1 v1.5 Padding) ---\n";
        std::cout << u8"1. Сгенерировать и сохранить ключи\n";
        std::cout << u8"2. Зашифровать файл\n";
        std::cout << u8"3. Расшифровать файл\n";
        std::cout << u8"4. Зашифровать текст\n";
        std::cout << u8"5. Расшифровать текст\n";
        std::cout << u8"6. Назад\n";
        int choice = get_menu_choice(1, 6);
        if (choice == 1) {
            std::cout << u8"Введите длину ключа в битах (например, 2048): ";
            int bits;
            std::cin >> bits;
            clear_cin();
            std::cout << u8"Генерация ключей... Это может занять некоторое время.\n";
            if (generate_keys(bits, "public.key", "private.key")) {
                std::cout << u8"Ключи успешно сгенерированы и сохранены в файлы public.key и private.key.\n";
            } else {
                 std::cerr << u8"Не удалось сгенерировать ключи.\n";
            }
        } else if (choice == 2) {
            std::string key_path, in_path, out_path;
            std::cout << u8"Путь к файлу публичного ключа (public.key): "; std::getline(std::cin, key_path);
            std::cout << u8"Путь к исходному файлу для шифрования: "; std::getline(std::cin, in_path);
            std::cout << u8"Путь к целевому зашифрованному файлу: "; std::getline(std::cin, out_path);
            if (encrypt_file(key_path.c_str(), in_path.c_str(), out_path.c_str())) {
                std::cout << u8"Файл успешно зашифрован.\n";
            } else {
                std::cerr << u8"Ошибка шифрования файла.\n";
            }
        } else if (choice == 3) {
            std::string key_path, in_path, out_path;
            std::cout << u8"Путь к файлу приватного ключа (private.key): "; std::getline(std::cin, key_path);
            std::cout << u8"Путь к зашифрованному файлу: "; std::getline(std::cin, in_path);
            std::cout << u8"Путь для сохранения расшифрованного файла: "; std::getline(std::cin, out_path);
            if (decrypt_file(key_path.c_str(), in_path.c_str(), out_path.c_str())) {
                std::cout << u8"Файл успешно расшифрован.\n";
            } else {
                 std::cerr << u8"Ошибка расшифрования файла.\n";
            }
        } else if (choice == 4) {
            std::string key_path, plaintext;
            std::cout << u8"Путь к файлу публичного ключа (public.key): "; std::getline(std::cin, key_path);
            std::cout << u8"Введите текст для шифрования: "; std::getline(std::cin, plaintext);
            char* result = encrypt_text(key_path.c_str(), plaintext.c_str());
            if (result) {
                std::cout << u8"Зашифрованный текст (HEX):\n" << result << std::endl;
                free_string(result);
            } else {
                std::cerr << u8"Ошибка шифрования текста.\n";
            }
        } else if (choice == 5) {
            std::string key_path, ciphertext;
            std::cout << u8"Путь к файлу приватного ключа (private.key): "; std::getline(std::cin, key_path);
            std::cout << u8"Введите зашифрованный текст (HEX, блоки через пробел): "; std::getline(std::cin, ciphertext);
            char* result = decrypt_text(key_path.c_str(), ciphertext.c_str());
             if (result) {
                std::cout << u8"Расшифрованный текст:\n" << result << std::endl;
                free_string(result);
            } else {
                std::cerr << u8"Ошибка расшифрования текста.\n";
            }
        }
    }
#ifdef _WIN32
    FreeLibrary((HMODULE)handle);
#else
    dlclose(handle);
#endif
}

int main() {
    setup_windows_console();
    while (true) {
        std::cout << u8"\n====== Программа шифрования ======\n";
        std::cout << u8"Выберите шифр:\n";
        std::cout << u8"1. Полибий\n";
        std::cout << u8"2. Атбаш\n";
        std::cout << u8"3. RSA\n";
        std::cout << u8"4. Выход\n";

        int choice = get_menu_choice(1, 4);
        switch (choice) {
            case 1: run_polybius_menu(); break;
            case 2: run_atbash_menu(); break;
            case 3: run_rsa_menu(); break;
            case 4:
                std::cout << u8"Выход из программы." << std::endl;
                return 0;
        }
    }
    return 0;
}

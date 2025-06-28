#include "atbash.h"
#include <vector>
#include <locale>
#include <fstream>
#include <sstream>
#include <codecvt>

// Конвертер вынесен сюда для переиспользования
static std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;

std::wstring AtbashCipher::transform_text(const std::wstring& w_text) const {
    std::wstring w_result = L"";
    for (wchar_t wc : w_text) {
        if (wc >= L'a' && wc <= L'z') {
            w_result += L'z' - (wc - L'a');
        } else if (wc >= L'A' && wc <= L'Z') {
            w_result += L'Z' - (wc - L'A');
        } else if (wc >= L'а' && wc <= L'я') {
            w_result += L'я' - (wc - L'а');
        } else if (wc >= L'А' && wc <= L'Я') {
            w_result += L'Я' - (wc - L'А');
        } else {
            w_result += wc;
        }
    }
    return w_result;
}

void AtbashCipher::transform_file(const std::string& input_path, const std::string& output_path) const {
    std::ifstream input_file(input_path, std::ios::binary);
    if (!input_file) {
        // В реальном приложении здесь лучше выбрасывать исключение
        return;
    }

    // Читаем весь файл в строку
    std::stringstream buffer;
    buffer << input_file.rdbuf();
    std::string content = buffer.str();
    input_file.close();

    // Конвертируем в wstring, трансформируем, конвертируем обратно
    std::wstring w_content = converter.from_bytes(content);
    std::wstring w_transformed = transform_text(w_content);
    std::string transformed_content = converter.to_bytes(w_transformed);

    // Записываем результат в выходной файл
    std::ofstream output_file(output_path, std::ios::binary);
    if (!output_file) {
        return;
    }
    output_file.write(transformed_content.c_str(), transformed_content.length());
    output_file.close();
}

#include "sample-windows-0002.h"

enum class RETURN_CODE : int
{
    SUCCESS = 0x00,
    FAILURE = 0x01,
};

int main(int argc, char *argv[])
{
    std::vector<std::string> args(argv, argv + argc);

    std::string filePath;

    for (std::vector<std::string>::iterator iter = args.begin(); iter != args.end(); iter++)
    {
        if (iter->compare("-f") == 0x00 && ++iter != args.end())
        {
            filePath = *iter;
            continue;
        }
    }

    if (filePath.empty() || std::filesystem::exists(filePath) == false)
        return static_cast<int>(RETURN_CODE::FAILURE);

    {
        // ooxml file magic number: 50 4B 03 04
        const std::vector<unsigned char> MAGIC_OOXML = {0x50, 0x4B, 0x03, 0x04};
        std::ifstream file(filePath, std::ios::binary);

        if (file.is_open() == false)
            return static_cast<int>(RETURN_CODE::FAILURE);

        std::vector<unsigned char> header(0x0A);
        file.read(reinterpret_cast<char *>(header.data()), header.size());

        for (size_t i = 0x00; i < MAGIC_OOXML.size(); i++)
        {
            if (header[i] != MAGIC_OOXML[i])
                return static_cast<int>(RETURN_CODE::FAILURE);
        }
    }

    std::set<std::string> extractedFiles;

    {
        unzFile zip = unzOpen(filePath.c_str());

        if (zip == nullptr)
            return static_cast<int>(RETURN_CODE::FAILURE);

        if (unzGoToFirstFile(zip) != UNZ_OK)
        {
            unzClose(zip);
            return static_cast<int>(RETURN_CODE::FAILURE);
        }

        do
        {
            std::string filename(260, '\0');
            unz_file_info fileInfo = {};

            if (unzGetCurrentFileInfo(
                    zip, &fileInfo, filename.data(), (uLong)filename.size(),
                    nullptr, 0x00, nullptr, 0x00) != UNZ_OK)
                continue;

            filename.resize(strlen(filename.c_str()));

            if (filename.back() == '/' || filename.back() == '\\')
            {
                std::filesystem::create_directories(filename);
                continue;
            }

            auto parent = std::filesystem::path(filename).parent_path();

            if (parent.empty() == false && std::filesystem::exists(parent) == false)
                std::filesystem::create_directories(parent);

            if (unzOpenCurrentFile(zip) != UNZ_OK)
                continue;

            FILE* out = fopen(filename.c_str(), "wb");

            if (out == nullptr)
            {
                unzCloseCurrentFile(zip);
                continue;
            }

            std::vector<char> buffer(64 * 1024);
            int bytesRead = 0x00;

            while ((bytesRead = unzReadCurrentFile(zip, buffer.data(), (unsigned int)buffer.size())) > 0x00)
            {
                fwrite(buffer.data(), bytesRead, 0x01, out);
            }

            extractedFiles.insert(filename);

            fclose(out);
            unzCloseCurrentFile(zip);
        } while (unzGoToNextFile(zip) == UNZ_OK);

        unzClose(zip);
    }

    ooxml::DocxConverter converter(extractedFiles);
    converter.ConvertToPdf("output.pdf");

    return static_cast<int>(RETURN_CODE::SUCCESS);
}
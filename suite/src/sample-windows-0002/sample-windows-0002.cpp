#include "sample-windows-0002.h"

int main()
{
    unzFile zip = unzOpen("sample.docx");
    tinyxml2::XMLDocument doc;
    HPDF_Doc pdf = HPDF_New(nullptr, nullptr);


    return 0x00;
}
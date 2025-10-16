#include "docx_converter.h"

namespace ooxml
{
    DocxConverter::DocxConverter(const std::set<std::string> &extractedFiles) : m_extractedFiles(extractedFiles) {}

    bool DocxConverter::ConvertToPdf(const std::string &outputPath)
    {
        if (m_extractedFiles.find("word/document.xml") == m_extractedFiles.end())
            return false;

        std::vector<DOCX_ELEMENT> elements = ParseDocument();

        if (elements.empty())
            return false;

        return true;
    }

    std::vector<DOCX_ELEMENT> DocxConverter::ParseDocument()
    {
        std::vector<DOCX_ELEMENT> elements;
        tinyxml2::XMLDocument doc;

        if (doc.LoadFile("word/document.xml") != tinyxml2::XML_SUCCESS)
            return elements;

        tinyxml2::XMLElement *body = doc.RootElement()->FirstChildElement("w:body");

        if (body == nullptr)
            return elements;

        ParseDocumentInternal(body, elements);

        return elements;
    }

    void DocxConverter::ParseDocumentInternal(
        tinyxml2::XMLElement* element,
        std::vector<DOCX_ELEMENT>& elements,
        const std::string &parentName)
    {
        if (element == nullptr)
            return;

        const char *raw = element->Name();
        std::string name = raw ? raw : "";

        DOCX_ELEMENT e = {};

        if (name.compare("w:p") == 0x00)
        {
            e.type = DOCX_ELEMENT::TYPE::PARAGRAPH_BREAK;
            elements.push_back(e);
        }
        else if (name.compare("w:tbl") == 0x00)
        {
            e.type = DOCX_ELEMENT::TYPE::TABLE;
            elements.push_back(e);
        }
        else if (parentName.compare("w:r") == 0x00 && name.compare("w:t") == 0x00)
        {
            raw = element->GetText();
            std::string text = raw ? raw : "";

            e.type = DOCX_ELEMENT::TYPE::TEXT;
            e.data.insert(e.data.end(), text.begin(), text.end());
            elements.push_back(e);
        }
        else if (parentName.compare("w:pPr") == 0x00 && name.compare("w:jc") == 0x00)
        {
            // center, left, right, both
            raw = element->Attribute("w:val");
            std::string wVal = raw ? raw : "";

            e.type = DOCX_ELEMENT::TYPE::UNKNOWN; // to do...
            e.data.insert(e.data.end(), wVal.begin(), wVal.end());
            elements.push_back(e);
        }
        else if (parentName.compare("w:drawing") == 0x00 && name.compare("wp:inline") == 0x00)
        {
            e.type = DOCX_ELEMENT::TYPE::IMAGE;

            tinyxml2::XMLElement* extent = element->FirstChildElement("wp:extent");

            if (extent != nullptr)
            {
                const char* cxAttr = extent->Attribute("cx");
                const char* cyAttr = extent->Attribute("cy");

                double width = cxAttr ? (std::stod(cxAttr) / 914400.0 * 72.0) : 0x00;
                double height = cyAttr ? (std::stod(cyAttr) / 914400.0 * 72.0) : 0x00;

                e.data.insert(e.data.end(), reinterpret_cast<unsigned char*>(&width), reinterpret_cast<unsigned char*>(&width) + sizeof(width));
                e.data.insert(e.data.end(), reinterpret_cast<unsigned char*>(&height), reinterpret_cast<unsigned char*>(&height) + sizeof(height));
            }

            // to do... (extent: 0x08 + 0x08) + image data

            elements.push_back(e);
        }

        for (tinyxml2::XMLElement* child = element->FirstChildElement();
            child;
            child = child->NextSiblingElement())
        {
            ParseDocumentInternal(child, elements, name);
        }
    }
}
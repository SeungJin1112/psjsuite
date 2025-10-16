#pragma once

#include "../../../lib/tinyxml2/tinyxml2.h"
#include "../../../lib/libharu/include/hpdf.h"

#include <map>
#include <set>
#include <string>
#include <vector>

namespace ooxml
{
    typedef struct _DOCX_ELEMENT
    {
        enum class TYPE : uint8_t
        {
            TEXT,
            BOLD_TEXT,
            HIGHLIGHT_TEXT,
            ITALIC_TEXT,
            UNDERLINE_TEXT,
            STRIKETHROUGH_TEXT,
            SUPERSCRIPT_TEXT,
            SUBSCRIPT_TEXT,
            PARAGRAPH_BREAK,
            LINE_BREAK,
            SECTION_BREAK,
            TAB,
            IMAGE,
            SHAPE,
            TABLE,
            TABLE_ROW,
            TABLE_CELL,
            LIST_ITEM,
            HYPERLINK,
            BOOKMARK,
            COMMENT,
            FOOTNOTE,
            ENDNOTE,
            UNKNOWN
        } type;
        std::vector<unsigned char> data;
    } DOCX_ELEMENT, *PDOCX_ELEMENT;

    static const std::set<std::string> DOCX_FILES =
    {
        "[Content_Types].xml",
        "_rels/.rels",
        "word/document.xml",
        "word/endnotes.xml",
        "word/fontTable.xml",
        "word/footer1.xml",
        "word/footer2.xml",
        "word/footer3.xml",
        "word/footnotes.xml",
        "word/header1.xml",
        "word/header2.xml",
        "word/header3.xml",
        "word/numbering.xml",
        "word/settings.xml",
        "word/styles.xml",
        "word/webSettings.xml",
        "word/_rels/document.xml.rels"
        "word/_rels/footer1.xml.rels",
        "word/_rels/footer2.xml.rels",
        "word/_rels/footer3.xml.rels",
        "word/_rels/header1.xml.rels",
        "word/_rels/header2.xml.rels",
        "word/_rels/header3.xml.rels",
        "word/theme/theme1.xml",
    };

    class DocxConverter
    {
    private:
        std::set<std::string> m_extractedFiles;

    private:
        std::vector<DOCX_ELEMENT> ParseDocument();
        void ParseDocumentInternal(
            tinyxml2::XMLElement* element,
            std::vector<DOCX_ELEMENT>& elements,
            const std::string &parentName = "");

    public:
        DocxConverter(const std::set<std::string> &extractedFiles);
        virtual ~DocxConverter() = default;

        bool ConvertToPdf(const std::string &outputPath);
    };
}
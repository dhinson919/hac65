//
// HAC/65 6502 Inferencing Disassembler
//
// This work is licensed under the MIT License <https://opensource.org/licenses/MIT>
// Copyright 2018 David Hinson <https://github.com/dhinson919>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
// Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// Portions of this work are derived from the RSA Data Security, Inc. MD5 Message-Digest Algorithm
//

#include "IHac65.hpp"
#include "common.hpp"

namespace Hac65
{

const char *kUsageText
    {
        "usage: hac65 [options] object-file\n"
        "Options:\n"
        "  -h               Display this information\n"
        "  -v               Display version\n"
        "  -S <digits>      Starting position within object\n"
        "  -E <digits>      Ending position within object\n"
        "  -A <aro-name>    Top architecture overlay\n"
        "  -o <digits>      Origin address\n"
        "  -i               Illuminate dark code\n"
        "  -R [sfdo]        Reporting options\n"
        "                     s = segments\n"
        "                     f = segment fingerprints\n"
        "                     d = disassembly\n"
        "                     o = overlays\n"
    };

const char *kVersionText{"HAC/65 v0.5 6502 Inferencing Disassembler"};

const char *kFlexIntSyntax{"^[-+]?(([1-9][0-9]{0,4})|(\\$|0[Xx])([0-9A-Fa-f]{1,4})|(')(.)|(0[0-7]{0,6}))$"};

uint16_t
FlexIntToUint16 (const std::string &flexInt)
{
    uint16_t result{};
    std::string value{flexInt};
    std::regex syntax(kFlexIntSyntax);
    if (std::regex_search(value, syntax))
    {
        switch (value[0])
        {
            case '$': value.replace(0, 1, "0x"); break;
            case '\'': value.replace(0, 2, std::to_string(value[1])); break;
            default: break;
        }
        result = static_cast<uint16_t>(::strtoul(value.c_str(), nullptr, 0));
    }
    else
    {
        std::ostringstream text;
        text << "invalid digits: '" << flexInt << '\'';
        throw Hac65Exception(text.str());
    }
    return result;
}

}

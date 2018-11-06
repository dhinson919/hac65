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

#include <fstream>
#include <iomanip>

#include "IHac65.hpp"
#include "Loader.hpp"

namespace Hac65
{

uint16_t
Loader::JsonValueToUint16 (const json &json) const
{
    uint16_t result{0};
    if (json.is_number())
        result = json;
    else if (json.is_string())
        result = FlexIntToUint16(json.get<std::string>());
    else
    {
        std::ostringstream text;
        text << "malformed value: " << json << std::endl;
        throw Hac65Exception(text.str());
    }
    return result;
}

void
Loader::LoadAroJson (const std::string &architecture, const json &aroJson)
{
    for (auto topItor{std::begin(aroJson)}; topItor != std::end(aroJson); ++topItor)
    {
        const auto &topKey{topItor.key()};
        if (topKey == "origin")
        {
            const auto &topValue{topItor.value()};
            if (!topValue.is_number() && !topValue.is_string())
            {
                std::ostringstream text;
                text << "malformed origin spec: " << topValue << std::endl;
                throw OverlayError(text.str());
            }
            Address address{static_cast<Address>(JsonValueToUint16(topValue))};
            if (!_pAnalyzer->HasOriginAddress())
                _pAnalyzer->DeclareOriginAddress(address);
        }
        else if (topKey == "equates")
        {
            const auto &topValue{topItor.value()};
            if (!topValue.is_object())
            {
                std::ostringstream text;
                text << "malformed equates spec: " << topValue << std::endl;
                throw OverlayError(text.str());
            }
            for (auto equateItor{std::begin(topValue)}; equateItor != std::end(topValue); ++equateItor)
            {
                const auto &equate{equateItor.key()};
                const auto &value{equateItor.value()};
                uint16_t equateInt{JsonValueToUint16(value)};
                _pAnalyzer->DeclareEquate(equate, equateInt);
            }
        }
        else if (topKey == "code_labels")
        {
            const auto &topValue{topItor.value()};
            if (!topValue.is_object())
            {
                std::ostringstream text;
                text << "malformed code labels spec: " << topValue << std::endl;
                throw OverlayError(text.str());
            }
            for (auto labelItor{std::begin(topValue)}; labelItor != std::end(topValue); ++labelItor)
            {
                const auto &label{labelItor.key()};
                const auto &addressJson{labelItor.value()};
                Address address{static_cast<Address>(JsonValueToUint16(addressJson))};
                _pAnalyzer->DeclareCodeLabel(label, address);
            }
        }
        else if (topKey == "data_labels")
        {
            const auto &topValue{topItor.value()};
            if (!topValue.is_object())
            {
                std::ostringstream text;
                text << "malformed data labels spec: " << topValue << std::endl;
                throw OverlayError(text.str());
            }
            for (auto labelItor{std::begin(topValue)}; labelItor != std::end(topValue); ++labelItor)
            {
                const auto &label{labelItor.key()};
                const auto &addressJson{labelItor.value()};
                Address address{static_cast<Address>(JsonValueToUint16(addressJson))};
                _pAnalyzer->DeclareDataLabel(label, address);
            }
        }
        else if (topKey == "structures")
        {
            const auto &topValue{topItor.value()};
            if (!topValue.is_object())
            {
                std::ostringstream text;
                text << "malformed structures spec: " << topValue << std::endl;
                throw OverlayError(text.str());
            }
            for (auto structureItor{std::begin(topValue)}; structureItor != std::end(topValue); ++structureItor)
            {
                const auto &structure{structureItor.value()};
                if (!structure.is_object())
                {
                    std::ostringstream text;
                    text << "malformed structure spec: " << structure << std::endl;
                    throw OverlayError(text.str());
                }
                const std::string &structureKey{structureItor.key()};
                auto kind{LookupStructureKind(structureKey)};
                if (kind != SK__Unknown)
                {
                    const auto &tables{structureItor.value()};
                    if (!tables.is_object())
                    {
                        std::ostringstream text;
                        text << "malformed tables spec: " << tables << std::endl;
                        throw OverlayError(text.str());
                    }
                    for (auto tableItor{std::begin(tables)}; tableItor != std::end(tables); ++tableItor)
                    {
                        const auto &addressJson{tableItor.key()};
                        Address address{static_cast<Address>(JsonValueToUint16(addressJson))};
                        auto count{JsonValueToUint16(tableItor.value())};
                        switch (kind)
                        {
                            case SK_NormalVectorTable:
                                _pAnalyzer->DeclareNormalVectorTable(address, count);
                                break;
                            case SK_IndirectVectorTable:
                                _pAnalyzer->DeclareIndirectVectorTable(address, count);
                                break;
                            case SK_KeyedVectorTable:
                                _pAnalyzer->DeclareKeyedVectorTable(address, count);
                                break;
                            case SK_KeyedIndirectVectorTable:
                                _pAnalyzer->DeclareKeyedIndirectVectorTable(address, count);
                                break;
                            case SK_KeyedIndirectMinusOneVectorTable:
                                _pAnalyzer->DeclareKeyedIndirectMinusOneVectorTable(address, count);
                                break;
                            case SK_JumpVectorTable:
                                _pAnalyzer->DeclareJumpVectorTable(address, count);
                                break;
                            case SK_MinusOneVectorTable:
                                _pAnalyzer->DeclareMinusOneVectorTable(address, count);
                                break;
                            case SK_SplitVectorTable:
                                _pAnalyzer->DeclareSplitVectorTable(address, count);
                                break;
                            default:
                                {
                                    std::ostringstream text;
                                    text << "unsupported vector table kind: " << kind << std::endl;
                                    throw OverlayError(text.str());
                                }
                                break;
                        }
                    }
                }
                else
                {
                    std::ostringstream text;
                    text << "unknown vector table kind: " << structureKey << std::endl;
                    throw OverlayError(text.str());
                }
            }
        }
        else if (topKey == "expert")
        {
            const auto &topValue{topItor.value()};
            if (!topValue.is_object())
            {
                std::ostringstream text;
                text << "malformed expert spec: " << topValue << std::endl;
                throw OverlayError(text.str());
            }
            for (auto expertItor{std::begin(topValue)}; expertItor != std::end(topValue); ++expertItor)
            {
                const auto &expertKey{expertItor.key()};
                const auto &expertValue{expertItor.value()};
                if (expertKey == "lands")
                {
                    if (!expertValue.is_array())
                    {
                        std::ostringstream text;
                        text << "malformed lands spec: " << expertValue << std::endl;
                        throw OverlayError(text.str());
                    }
                    for (auto landsItor{std::begin(expertValue)}; landsItor != std::end(expertValue); ++landsItor)
                    {
                        const auto &landValue{landsItor.value()};
                        if (!landValue.is_number() && !landValue.is_string())
                        {
                            std::ostringstream text;
                            text << "malformed land value: " << landValue << std::endl;
                            throw OverlayError(text.str());
                        }
                        Address address{static_cast<Address>(JsonValueToUint16(landValue))};
                        _pAnalyzer->DeclareLand(address);
                    }
                }
                else if (expertKey == "leaps")
                {
                    if (!expertValue.is_array())
                    {
                        std::ostringstream text;
                        text << "malformed leaps spec: " << expertValue << std::endl;
                        throw OverlayError(text.str());
                    }
                    for (auto leapsItor{std::begin(expertValue)}; leapsItor != std::end(expertValue); ++leapsItor)
                    {
                        const auto &leapValue{leapsItor.value()};
                        if (!leapValue.is_number() && !leapValue.is_string())
                        {
                            std::ostringstream text;
                            text << "malformed leap value: " << leapValue << std::endl;
                            throw OverlayError(text.str());
                        }
                        Address address{static_cast<Address>(JsonValueToUint16(leapValue))};
                        _pAnalyzer->DeclareLeap(address);
                    }
                }
                else
                {
                    std::ostringstream text;
                    text << "unknown expert spec: " << expertKey << std::endl;
                    throw OverlayError(text.str());
                }
            }
        }
        else
        {
            std::ostringstream text;
            text << "unknown spec: " << topKey << std::endl;
            throw OverlayError(text.str());
        }
    }

    _overlays.push_front({architecture, aroJson});
}

const char *kIncludeDirectiveSyntax{R"(^\@(include)[\s]*["][A-Za-z0-9._-]{1,20}["])"};

void
Loader::LoadAroStream (std::ifstream &aroStream, const std::string &architecture, int depth)
{
    if (depth > 10)
    {
        std::ostringstream text;
        text << "max architecture overlay depth of 10 exceeded by " << architecture << std::endl;
        throw OverlayError(text.str());
    }

    std::stringstream jsonStream;
    std::string line;
    while (std::getline(aroStream, line))
    {
        auto commentPos{line.find('#')};
        if (commentPos != std::string::npos)
            line = line.substr(0, commentPos);

        std::regex include(kIncludeDirectiveSyntax, std::regex_constants::icase);
        std::smatch match;
        if (std::regex_search(line, match, include))
        {
            auto startQuote{match.str().find('"') + 1};
            auto endQuote{match.str().rfind('"')};
            std::string nextArchitecture{match.str().substr(startQuote, endQuote - startQuote)};
            LoadAroFile(nextArchitecture, depth + 1);
        }
        else
        {
            if (line[0] == '@')
            {
                std::ostringstream text;
                text << "invalid architecture overlay directive '" << line << "' in " << architecture << std::endl;
                throw OverlayError(text.str());
            }
            else
                jsonStream << line.c_str() << std::endl;
        }
    }

    json aroJson;
    try
    {
        jsonStream >> aroJson;
    }
    catch (json::exception &exc)
    {
        std::ostringstream text;
        text << "architecture overlay " << architecture << ": " <<
            exc.what() << std::endl;
        throw OverlayError(text.str());
    }

    try
    {
        LoadAroJson(architecture, aroJson);
    }
    catch (Hac65Exception &exc)
    {
        std::ostringstream text;
        text << "architecture overlay " << architecture << ": " <<
            exc.what() << std::endl;
        throw OverlayError(text.str());
    }

}

bool
Loader::LoadBuiltinArchitecture (const std::string &architecture)
{
    bool result{false};
    auto itor = kBuiltinArchitectures.find(architecture);
    if (itor != std::end(kBuiltinArchitectures))
    {
        const json &aroJson{itor->second};
        LoadAroJson(architecture, aroJson);
        result = true;
    }
    return result;
}

void
Loader::LoadAroFile (const std::string &architecture, int depth)
{
    const auto aroFilename{architecture + ".aro"};
    std::ifstream arcStream(aroFilename);
    bool isOpen{arcStream.is_open()};
    if (isOpen)
        LoadAroStream(arcStream, architecture, depth);
    else if (!LoadBuiltinArchitecture(architecture))
    {
        std::ostringstream text;
        text << "cannot find .aro file for '" << architecture << '\'';
        throw OverlayError(text.str());
    }
}

void
Loader::LoadArchitecture ()
{
    const auto architecture{GetArchitecture()};
    int depth{0};
    LoadAroFile(architecture, depth + 1);
}

void
Loader::LoadObjectFile ()
{
    std::ifstream objectFile(_objectFilename, std::ios::in | std::ios::binary | std::ios::ate);
    if (objectFile.is_open())
    {
        std::streamoff objectFileSize{objectFile.tellg()};

        auto startPosition{GetStartPosition()};
        if (startPosition >= objectFileSize)
        {
            std::ostringstream text;
            text << std::hex << std::uppercase;
            text << "invalid start position $"  << startPosition <<
                " (exceeds object file size $" << objectFileSize << ")" << std::endl;
            throw UsageError(text.str());
        }

        auto endPosition{GetEndPosition()};
        if (endPosition == -1)
            endPosition = objectFileSize - 1;
        if (endPosition < startPosition)
        {
            std::ostringstream text;
            text << std::hex << std::uppercase;
            text << "invalid start position $"  << startPosition <<
                " (exceeds end position $" << endPosition << ")" << std::endl;
            throw UsageError(text.str());
        }
        if (endPosition >= objectFileSize)
        {
            std::ostringstream text;
            text << std::hex << std::uppercase;
            text << "invalid end position $"  << endPosition <<
                " (exceeds object file size $" << objectFileSize << ")" << std::endl;
            throw UsageError(text.str());
        }

        _objectSize = endPosition - startPosition + 1;
        if (_objectSize > kMaxObjectSize)
        {
            std::ostringstream text;
            text << std::hex << std::uppercase;
            text << "invalid object size $"  << _objectSize <<
                " (exceeds max object size $" << kMaxObjectSize << ")" << std::endl;
            throw UsageError(text.str());
        }

        _object.resize(static_cast<size_t>(_objectSize));
        objectFile.seekg(startPosition, std::ios::beg);
        objectFile.read(reinterpret_cast<char *>(_object.data()), _objectSize);

        objectFile.close();

        _objectMd5.update(_object.data(), static_cast<MD5::size_type>(_objectSize));
        _objectMd5.finalize();
    }
    else
    {
        std::ostringstream text;
        text << "cannot find object-file '" << _objectFilename << '\'';
        throw UsageError(text.str());
    }
}

void
Loader::Load (std::shared_ptr<IAnalyzer> pAnalyzer)
{
    _pAnalyzer = std::move(pAnalyzer);

    LoadArchitecture();
    LoadObjectFile();

    _pAnalyzer->SetAssembly(std::move(_object));
}

}

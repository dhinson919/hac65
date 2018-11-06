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

#ifndef HAC65_LOADER_HPP
#define HAC65_LOADER_HPP

#include <list>
#include <optional>
#include <regex>
#include <string>
#include <vector>

#include "md5.h"

#include "common.hpp"
#include "IAnalyzer.hpp"
#include "IHac65.hpp"
#include "ILoader.hpp"

namespace Hac65
{

class Loader : public ILoader
{
    enum StructureKind
    {
        SK__Unknown,
        SK_NormalVectorTable,
        SK_IndirectVectorTable,
        SK_KeyedVectorTable,
        SK_KeyedIndirectVectorTable,
        SK_KeyedIndirectMinusOneVectorTable,
        SK_JumpVectorTable,
        SK_MinusOneVectorTable,
        SK_SplitVectorTable
    };
    const std::unordered_map<std::string, StructureKind> kStructureKinds
        {
            {"normal_vector_tables", SK_NormalVectorTable},
            {"indirect_vector_tables", SK_IndirectVectorTable},
            {"keyed_vector_tables", SK_KeyedVectorTable},
            {"keyed_indirect_vector_tables", SK_KeyedIndirectVectorTable},
            {"keyed_indirect_minus_one_vector_tables", SK_KeyedIndirectMinusOneVectorTable},
            {"jump_vector_tables", SK_JumpVectorTable},
            {"minus_one_vector_tables", SK_MinusOneVectorTable},
            {"split_vector_tables", SK_SplitVectorTable}
        };

    const std::unordered_map<std::string, json> kBuiltinArchitectures
        {
            {"Builtin_MOS6502",
                {{"structures",
                    {{"normal_vector_tables",
                        {{"$FFFA", 3}}}
                    }
                 }}
            }
        };

    const std::string kDefaultArchitecture{"Builtin_MOS6502"};
    const std::streampos kDefaultStartPosition{0};
    const std::streampos kDefaultEndPosition{-1};
    const size_t kMaxObjectSize{0x10000};

    std::optional<std::string> _architectureOpt;

    std::optional<std::streampos> _startPositionOpt;

    std::optional<std::streampos> _endPositionOpt;

    std::string _objectFilename;

    std::streamoff _objectSize{0};

    std::vector<Octet> _object;

    MD5 _objectMd5{};

    std::list<std::pair<std::string, json>> _overlays;

    std::shared_ptr<IAnalyzer> _pAnalyzer;

    std::string
    GetArchitecture () const
    {
        return _architectureOpt.value_or(kDefaultArchitecture);
    }

    std::streampos
    GetEndPosition () const
    {
        return _endPositionOpt.value_or(kDefaultEndPosition);
    }

    std::streampos
    GetStartPosition () const
    {
        return _startPositionOpt.value_or(kDefaultStartPosition);
    }

    uint16_t
    JsonValueToUint16 (const json &json) const;

    void
    LoadAroJson (const std::string &architecture, const json &aroJson);

    void
    LoadAroStream (std::ifstream &aroStream, const std::string &architecture, int depth);

    void
    LoadAroFile (const std::string &architecture, int depth);

    void
    LoadArchitecture ();

    bool
    LoadBuiltinArchitecture (const std::string &architecture);

    void
    LoadObjectFile ();

    StructureKind
    LookupStructureKind (const std::string &key) const
    {
        auto kindItor{kStructureKinds.find(key)};
        return (kindItor == std::end(kStructureKinds)) ? SK__Unknown : kindItor->second;
    }

    MD5
    GetObjectMd5 () const override
    {
        return _objectMd5;
    }

    const std::list<std::pair<std::string, json>> &
    GetOverlays () const override
    {
        return _overlays;
    }

    void
    Load (std::shared_ptr<IAnalyzer> pAnalyzer) override;

    void
    SetArchitecture (const std::string &architecture) override
    {
        _architectureOpt = std::optional<std::string>(architecture);
    }

    void
    SetEndPosition (std::streampos position) override
    {
        _endPositionOpt = std::optional<std::streampos>(position);
    }

    void
    SetObjectFilename (std::string filename) override
    {
        _objectFilename = std::move(filename);
    }

    void
    SetStartPosition (std::streampos position) override
    {
        _startPositionOpt = std::optional<std::streampos>(position);
    }
};

}

#endif //HAC65_LOADER_HPP

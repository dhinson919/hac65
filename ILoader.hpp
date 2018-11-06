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

#ifndef HAC65_ILOADER_HPP
#define HAC65_ILOADER_HPP

#include <ios>
#include <list>
#include <string>
#include <utility>

#include "nlohmann/json.hpp"
using json = nlohmann::json;
#include "md5.h"

#include "IAnalyzer.hpp"

namespace Hac65
{

struct ILoader
{
    virtual MD5
    GetObjectMd5 () const = 0;

    virtual const std::list<std::pair<std::string, json>> &
    GetOverlays () const = 0;

    virtual void
    Load (std::shared_ptr<IAnalyzer> pAnalyzer) = 0;

    virtual void
    SetArchitecture (const std::string &architecture) = 0;

    virtual void
    SetEndPosition (std::streampos position) = 0;

    virtual void
    SetObjectFilename (std::string filename) = 0;

    virtual void
    SetStartPosition (std::streampos position) = 0;
};

}

#endif //HAC65_ILOADER_HPP

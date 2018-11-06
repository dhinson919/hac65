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

#ifndef HAC65_REPORTER_HPP
#define HAC65_REPORTER_HPP

#include <string>

#include "md5.h"

#include "IReporter.hpp"
#include "common.hpp"
#include "IAnalyzer.hpp"
#include "ILoader.hpp"
#include "IHac65.hpp"

namespace Hac65
{

class Reporter : public IReporter
{
    const std::string kAllReportFlags{"sdfo"};

    std::string _reportFlags{"s"};

    std::shared_ptr<IAnalyzer> _pAnalyzer;

    std::shared_ptr<ILoader> _pLoader;

    std::string
    AddressToString (
        const Address &address,
        std::optional<Opcode> opcodeOpt = std::nullopt,
        bool isSymbolic = false) const;

    std::string
    SegmentTypeToString (const Segment::Type &type) const;

    size_t
    DisassembleInstruction (
        const Address &address,
        const Instruction &instruction,
        std::string &rawDisassembly,
        std::string &cookedDisassembly) const;

    void
    ReportDisassembly (std::ostream &ostream) const;

    void
    ReportFingerprints (std::ostream &ostream) const;

    void
    ReportHeader (
        const std::string &timeText,
        const std::string &commandText,
        std::ostream &outStream);

    void
    ReportOverlays (std::ostream &ostream) const;

    void
    ReportSegments (std::ostream &ostream) const;

    void
    StreamAddress (std::ostream &ostream, const Address &address) const;

    void
    StreamCodeSegment (std::ostream &stream, const Address &start, const Address &end) const;

    void
    StreamData (std::ostream &ostream, const Octet &octet, bool isDecorated = false) const;

    void
    StreamDataSegment (std::ostream &stream, const Address &start, const Address &end) const;

    void
    StreamIllegal (std::ostream &ostream, const Opcode &opcode) const;

    void
    StreamInstruction (std::ostream &ostream, const Instruction &instruction, const Address &address) const;

    void
    StreamLabel (std::ostream &ostream, const Address &address) const;

    void
    StreamOctets (std::ostream &ostream, const std::vector<Octet> &octets, bool isDecorated = false) const;

    void
    StreamOrigin (std::ostream &ostream) const;

public:
    void
    Report (
        std::shared_ptr<ILoader> pLoader,
        std::shared_ptr<IAnalyzer> pAnalyzer,
        const std::string &timeText,
        const std::string &commandText,
        std::ostream &outStream) override;

    void
    SetReportFlags (std::string reportFlags) override
    {
        if (reportFlags.empty())
            _reportFlags = kAllReportFlags;
        else
        {
            for (auto flag: reportFlags)
                if (kAllReportFlags.find(flag) == std::string::npos)
                {
                    std::ostringstream text;
                    text << "unknown report flag '" << flag << "' provided";
                    throw UsageError(text.str());
                }
            _reportFlags = std::move(reportFlags);
        }
    }
};

}

#endif //HAC65_REPORTER_HPP

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

#include <iomanip>
#include <set>

#include "Reporter.hpp"

namespace Hac65
{

std::string
Reporter::AddressToString (const Address &address, std::optional<Opcode> opcodeOpt, bool isSymbolic) const
{
    AddressMode addressMode{AM__Unknown};
    MemoryOperation memoryOperation{MO_None};
    if (opcodeOpt)
    {
        const auto opcodeInfo{_pAnalyzer->LookupOpcodeInfo(opcodeOpt.value())};
        addressMode = opcodeInfo._addressMode;
        memoryOperation = opcodeInfo._memoryOperation;
    }
    std::ostringstream str;
    str << std::hex << std::uppercase << std::setfill('0');
    if (addressMode == AM__Unknown)
        str << std::setw(4) << address;
    else
    {
        std::optional<std::string> labelOpt;
        if (isSymbolic && addressMode != AM_Immediate)
            labelOpt = _pAnalyzer->LookupLabel(address, memoryOperation);

        if (labelOpt)
            str << labelOpt.value();
        else
        {
            if (addressMode != AM_Immediate || address > 9)
            {
                str << '$';
                switch (addressMode)
                {
                    case AM_Absolute:
                    case AM_AbsoluteX:
                    case AM_AbsoluteY:
                    case AM_Indirect:
                        str << std::setw(4);
                        break;
                    default:
                        str << std::setw(2);
                        break;
                }
            }
            str << address;
        }
    }
    return str.str();
}

std::string
Reporter::SegmentTypeToString (const Segment::Type &type) const
{
    const char *result{""};
    switch (type)
    {
        case Segment::ST_CodeDark:
            result = "code_dark";
            break;
        case Segment::ST_CodeInferred:
            result = "code_inferred";
            break;
        case Segment::ST_CodeKnown:
            result = "code_known";
            break;
        case Segment::ST_DataInferred:
            result = "data_inferred";
            break;
        case Segment::ST_DataKnown:
            result = "data_known";
            break;
        default: assert(false);
    }
    return result;
}

void
Reporter::StreamAddress (std::ostream &ostream, const Address &address) const
{
    ostream << AddressToString(address);
}

void
Reporter::StreamData (std::ostream &ostream, const Octet &octet, bool isDecorated) const
{
    std::ios save(nullptr);
    save.copyfmt(ostream);

    ostream << std::hex << std::uppercase << std::setfill('0');
    if (isDecorated)
        ostream << ".BYTE $";
    ostream << std::setw(2) << static_cast<uint16_t>(octet);

    ostream.copyfmt(save);
}

void
Reporter::StreamOctets (std::ostream &ostream, const std::vector<Octet> &octets, bool isDecorated) const
{
    std::ios save(nullptr);
    save.copyfmt(ostream);

    ostream << std::hex << std::uppercase << std::setfill('0');
    for (int count{0}; count < 3; ++count)
    {
        if (count > 0)
            ostream << " ";
        if (count < octets.size())
        {
            if (isDecorated)
                ostream << '$';
            ostream << std::setw(2) << static_cast<uint16_t>(octets[count]);
            if (isDecorated && count < octets.size() - 2)
                ostream << ',';
        }
        else
            ostream << "  ";
    }

    ostream.copyfmt(save);
}

void
Reporter::StreamInstruction (std::ostream &ostream, const Instruction &instruction, const Address &address) const
{
    const MnemonicInfo &mnemonicInfo{_pAnalyzer->LookupMnemonicInfo(instruction._opcodeInfo._mnemonic)};
    ostream << mnemonicInfo._text << ' ';
    Operand operand{instruction._operand};
    const AddressMode &addressMode{instruction._opcodeInfo._addressMode};
    const AddressModeInfo &addressModeInfo{_pAnalyzer->LookupAddressModeInfo(addressMode)};
    ostream << addressModeInfo._operandPrefix;

    if (addressMode == AM_Immediate)
    {
        ostream << std::setw(8) << std::left << AddressToString(static_cast<Address>(operand), instruction._opcode);
        auto equateOpt{_pAnalyzer->LookupEquate(operand)};
        if (equateOpt)
        {
            ostream << ";";
            auto equates{equateOpt.value()};
            for (auto itor{equates.begin()}; itor != equates.end(); ++itor)
            {
                auto &equate{*itor};
                ostream << equate << '?';
                if ((itor + 1) != equates.end())
                    ostream << ", ";
            }
        }
    }
    else
    {
        if (addressMode == AM_Relative)
        {
            auto offset{static_cast<int8_t>(instruction._operand)};
            operand = address + addressModeInfo._operandSize + static_cast<uint16_t>(1) + offset;
        }
        if (addressModeInfo._operandSize > 0)
            ostream << AddressToString(static_cast<Address>(operand), instruction._opcode, true);
    }

    ostream << addressModeInfo._operandSuffix;
}

void
Reporter::StreamLabel (std::ostream &ostream, const Address &address) const
{
    const size_t kMaxLabelLength{14};

    std::ios save(nullptr);
    save.copyfmt(ostream);

    std::string label;
    ostream << std::left;
    std::optional<std::string> symbolOpt{_pAnalyzer->LookupLabel(address, std::nullopt)};
    if (symbolOpt)
    {
        std::string &symbol{symbolOpt.value()};
        if (symbol.size() > kMaxLabelLength)
        {
            symbol.resize(kMaxLabelLength + 1);
            symbol[kMaxLabelLength] = '/';
        }
        label = symbol;
    }

    ostream << std::setw(kMaxLabelLength + 2) << label;

    ostream.copyfmt(save);
}

void
Reporter::StreamCodeSegment (std::ostream &ostream, const Address &start, const Address &end) const
{
    auto instructions{_pAnalyzer->GetInstructions()};
    auto instructionItor{instructions.find(start)};
    for (; instructionItor != instructions.end() && instructionItor->first <= end; ++instructionItor)
    {
        const Address &address{instructionItor->first};
        StreamAddress(ostream, address);
        const Instruction &instruction{instructionItor->second};
        std::string rawDisassembly;
        std::string cookedDisassembly;
        DisassembleInstruction(address, instruction, rawDisassembly, cookedDisassembly);

        ostream << "  " << rawDisassembly << "  ";
        StreamLabel(ostream, address);
        ostream << " " << cookedDisassembly << std::endl;
    }
}

void
Reporter::StreamDataSegment (std::ostream &ostream, const Address &start, const Address &end) const
{
    std::ios save(nullptr);
    save.copyfmt(ostream);

    Address location{start};
    ostream << std::hex << std::uppercase << std::setfill('0');
    do
    {
        auto assembly{_pAnalyzer->GetAssembly()};
        auto originAddress{_pAnalyzer->GetOriginAddress()};
        ostream << std::setw(2) << (uint16_t) assembly[location - originAddress];
        if (location == end || (location > start && ((location - start + 1) % 16 == 0)))
            ostream << std::endl;
        else
            ostream << ' ';
    }
    while (location++ != end);

    ostream.copyfmt(save);
}

inline void
Reporter::StreamIllegal (std::ostream &ostream, const Opcode &opcode) const
{
    ostream << "???";
}

inline void
Reporter::StreamOrigin (std::ostream &ostream) const
{
    std::ios save(nullptr);
    save.copyfmt(ostream);

    ostream << std::setw(37) << "*= $";
    StreamAddress(ostream, _pAnalyzer->GetOriginAddress());
    ostream << std::endl;

    ostream.copyfmt(save);
}

size_t
Reporter::DisassembleInstruction (
    const Address &address,
    const Instruction &instruction,
    std::string &rawDisassembly,
    std::string &cookedDisassembly) const
{
    const auto originAddress{_pAnalyzer->GetOriginAddress()};
    const auto assembly{_pAnalyzer->GetAssembly()};
    std::vector<Octet> octets;
    octets.push_back(assembly[address - originAddress]);
    const AddressMode &addressMode{instruction._opcodeInfo._addressMode};
    const AddressModeInfo &addressModeInfo{_pAnalyzer->LookupAddressModeInfo(addressMode)};
    uint16_t index{address};
    for (int count{0}; count < addressModeInfo._operandSize; ++count)
        octets.push_back(assembly[++index - originAddress]);
    std::ostringstream lineStream;
    StreamOctets(lineStream, octets);
    rawDisassembly = lineStream.str();
    lineStream.str("");
    StreamInstruction(lineStream, instruction, address);
    cookedDisassembly = lineStream.str();
    return sizeof(Opcode) + addressModeInfo._operandSize;
}

void
Reporter::ReportDisassembly (std::ostream &ostream) const
{
    std::map<Address, std::string> cookedDisassembly;
    std::map<Address, std::string> rawDisassembly;
    std::ostringstream lineStream;

    size_t instructionCount{0};
    size_t instructionOctetsCount{0};
    auto instructions{_pAnalyzer->GetInstructions()};
    for (const auto &pair: instructions)
    {
        const Address &address{pair.first};
        const Instruction &instruction{pair.second};
        ++instructionCount;
        instructionOctetsCount +=
            DisassembleInstruction(address, instruction, rawDisassembly[address], cookedDisassembly[address]);
    }

    size_t illegalInstructionOctetsCount{0};
    const auto originAddress{_pAnalyzer->GetOriginAddress()};
    auto assembly{_pAnalyzer->GetAssembly()};
    auto illegals{_pAnalyzer->GetIllegals()};
    for (const auto &pair: illegals)
    {
        lineStream.str("");
        const Address &address{pair.first};
        const Opcode &opcode{assembly[address - originAddress]};
        illegalInstructionOctetsCount += sizeof opcode;
        StreamOctets(lineStream, {opcode});
        rawDisassembly[address] = lineStream.str();

        lineStream.str("");
        StreamIllegal(lineStream, opcode);
        cookedDisassembly[address] = lineStream.str();
    }

    size_t dataOctetsCount{0};
    auto data{_pAnalyzer->GetData()};
    for (const auto &pair: data)
    {
        lineStream.str("");
        const Address &address{pair.first};
        const Octet &octet{assembly[address - originAddress]};
        dataOctetsCount += sizeof octet;
        StreamOctets(lineStream, {octet});
        rawDisassembly[address] = lineStream.str();

        lineStream.str("");
        StreamData(lineStream, octet, true);
        cookedDisassembly[address] = lineStream.str();
    }

    ostream << std::endl <<
        "Disassembly Report" << std::endl <<
        "------------------" << std::endl <<
        "Assembly size (bytes) : " << _pAnalyzer->GetAssemblySize() << std::endl <<
        "  Instruction         : " << instructionOctetsCount << std::endl <<
        "  Illegal instruction : " << illegalInstructionOctetsCount << std::endl <<
        "  Data                : " << dataOctetsCount << std::endl <<
        "Instructions (count)  : " << instructionCount << std::endl << std::endl;
    StreamOrigin(ostream);
    ostream << std::endl;
    for (const auto &pair: rawDisassembly)
    {
        const Address &address{pair.first};
        StreamAddress(ostream, address);

        const std::string &rawLine{pair.second};

        auto cookedItor{cookedDisassembly.find(address)};
        assert(cookedItor != end(cookedDisassembly));
        const std::string &cookedLine{cookedItor->second};

        ostream << "  " << rawLine << "  ";
        StreamLabel(ostream, address);
        ostream << " " << cookedLine << std::endl;
    }
}

void
Reporter::ReportFingerprints (std::ostream &ostream) const
{
    auto segments{_pAnalyzer->GetSegments()};

    ostream << std::endl <<
        "Fingerprints Report" << std::endl <<
        "-------------------" << std::endl <<
        "Assembly size (bytes) : " << _pAnalyzer->GetAssemblySize() << std::endl <<
        "Segments (count)      : " << segments.size() << std::endl << std::endl;

    std::set<std::string> sorted;
    for (const auto &pair: segments)
    {
        const Segment &segment{pair.second};

        MD5 md5;
        if (segment.IsCode())
            md5 = _pAnalyzer->FingerprintCodeSegment(segment);
        else if (segment.IsData())
            md5 = _pAnalyzer->FingerprintDataSegment(segment);
        else
            assert(false);

        std::ostringstream str;
        str << std::left <<
            md5.hexdigest() << ' ' <<
            '#' << std::setw(4) << segment._ordinal << ' ' <<
            std::setw(13) << SegmentTypeToString(segment._type) <<
            ' ';
        StreamAddress(str, segment._startAddress);
        str << ' ';
        StreamLabel(str, segment._startAddress);
        str << std::endl;

        sorted.insert(str.str());
    }

    for (const auto &line: sorted)
        ostream << line;
}

void
Reporter::ReportOverlays (std::ostream &ostream) const
{
    const auto overlays{_pLoader->GetOverlays()};

    ostream << std::endl <<
        "Overlays Report" << std::endl <<
        "---------------" << std::endl <<
        "Overlays (count) : " << overlays.size() << std::endl;

    for (const auto &pair: overlays)
    {
        const auto &architecture{pair.first};
        const auto &json{pair.second};
        ostream << std::endl <<
            "# " << architecture << ':' << std::endl <<
            std::setw(2) << json << std::endl;
    }
}

void
Reporter::ReportSegments (std::ostream &ostream) const
{
    uint16_t segmentCount_codeDark{0};
    uint16_t segmentCount_codeInferred{0};
    uint16_t segmentCount_codeKnown{0};
    uint16_t segmentCount_dataInferred{0};
    uint16_t segmentCount_dataKnown{0};
    auto segments{_pAnalyzer->GetSegments()};
    for (const auto &pair: segments)
    {
        const Segment &segment{pair.second};
        switch (segment._type)
        {
            case Segment::ST_CodeDark:
                ++segmentCount_codeDark;
                break;
            case Segment::ST_CodeInferred:
                ++segmentCount_codeInferred;
                break;
            case Segment::ST_CodeKnown:
                ++segmentCount_codeKnown;
                break;
            case Segment::ST_DataInferred:
                ++segmentCount_dataInferred;
                break;
            case Segment::ST_DataKnown:
                ++segmentCount_dataKnown;
                break;
            default: assert(false);
        }
    }

    ostream << std::endl <<
        "Segments Report" << std::endl <<
        "---------------" << std::endl <<
        "Assembly size (bytes) : " << _pAnalyzer->GetAssemblySize() << std::endl <<
        "Segments (count)      : " << segments.size() << std::endl <<
        "  Known Code          : " << segmentCount_codeKnown << std::endl <<
        "  Inferred Code       : " << segmentCount_codeInferred << std::endl <<
        "  Dark Code           : " << segmentCount_codeDark << std::endl <<
        "  Known Data          : " << segmentCount_dataKnown << std::endl <<
        "  Inferred Data       : " << segmentCount_dataInferred << std::endl << std::endl;
    StreamOrigin(ostream);

    for (const auto &pair: segments)
    {
        const Segment &segment{pair.second};

        MD5 md5;
        if (segment.IsCode())
            md5 = _pAnalyzer->FingerprintCodeSegment(segment);
        else if (segment.IsData())
            md5 = _pAnalyzer->FingerprintDataSegment(segment);
        else
            assert(false);

        ostream << std::endl <<
            "#" <<
            segment._ordinal <<
            " " <<
            AddressToString(segment._startAddress) <<
            '-' <<
            AddressToString(segment._endAddress) <<
            ' ' <<
            SegmentTypeToString(segment._type) <<
            ' ' <<
            md5.hexdigest() <<
            std::endl;

        if (segment.IsCode())
            StreamCodeSegment(ostream, segment._startAddress, segment._endAddress);
        else if (segment.IsData())
            StreamDataSegment(ostream, segment._startAddress, segment._endAddress);
        else
            assert(false);
    }
}

void
Reporter::ReportHeader (
    const std::string &timeText,
    const std::string &commandText,
    std::ostream &outStream)
{
    outStream <<
        kVersionText << " [run:" << timeText << ']' << std::endl <<
        commandText << "[md5:" << _pLoader->GetObjectMd5().hexdigest() << ']' << std::endl <<
        std::endl <<
        "Architecture Overlays:" << std::endl;
    const auto overlays{_pLoader->GetOverlays()};
    for (const auto &pair: overlays)
    {
        const auto &architecture{pair.first};
        outStream << "    " << architecture << std::endl;
    }
}

void
Reporter::Report (
    std::shared_ptr<ILoader> pLoader,
    std::shared_ptr<IAnalyzer> pAnalyzer,
    const std::string &timeText,
    const std::string &commandText,
    std::ostream &outStream)
{
    _pLoader = std::move(pLoader);
    _pAnalyzer = std::move(pAnalyzer);

    ReportHeader(timeText, commandText, outStream);

    for (auto flag: _reportFlags)
        switch (flag)
        {
            case 'd': ReportDisassembly(outStream); break;

            case 'f': ReportFingerprints(outStream); break;

            case 'o': ReportOverlays(outStream); break;

            case 's': ReportSegments(outStream); break;

            default: assert(false); break;
        }
}

}

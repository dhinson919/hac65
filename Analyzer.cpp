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

#include "IHac65.hpp"
#include "Analyzer.hpp"

namespace Hac65
{

Address
Analyzer::AddressToAssemblyOffset (const Address &address) const
{
    const auto originAddress{GetOriginAddress()};
    Address result{static_cast<Address>(address - originAddress)};
    if (result > _assemblySize)
    {
        std::ostringstream text;
        text << "encountered an out-of-object address ($" <<
            std::hex << std::uppercase << std::setfill('0') << address << ')' <<
            " -- is the origin address set correctly? (see -o option)";
        throw Hac65Exception(text.str());
    }
    return result;
}

void
Analyzer::AddJumpVectorLedges ()
{
    for (const auto &pair: _jumpVectorTables)
    {
        const Address &vectorAddress{pair.first};
        const uint16_t &vectorCount{pair.second};
        Address offset{0};
        for (uint16_t count{0}; count < vectorCount; ++count)
        {
            AddLand(vectorAddress + offset, Segment::ST_CodeKnown);
            AddLeap(vectorAddress + offset + sizeof(Operand));

            Address assemblyOffset{AddressToAssemblyOffset(vectorAddress + offset)};
            offset += (sizeof(Opcode) + sizeof(Operand));
            if (_assembly[assemblyOffset] != OpcodeInfo::JMP_Absolute)
                assert(false);
            Address landAddress{
                static_cast<Address>((_assembly[assemblyOffset + 2] << 8) | _assembly[assemblyOffset + 1])};
            AddLand(landAddress, Segment::ST_CodeKnown);
        }
    }
}

inline void
Analyzer::AddSegment (const Address &segmentAddress, const Segment &segment)
{
    _segments[segmentAddress] = {
        segment._type,
        segment._startAddress,
        segment._endAddress,
        _segments.size()};

    if (segment.IsData())
    {
        auto segmentLength{segment._endAddress - segment._startAddress + 1};
        for (auto count{0}; count < segmentLength; ++count)
        {
            const auto address{static_cast<Address>(segment._startAddress + count)};
            RemoveIllegal(address);
            RemoveInstruction(address);
        }
    }
}

void
Analyzer::AddVectorIndirections ()
{
    auto ftor{
        [this] (const Address &tableAddress, const uint16_t &entryCount, uint16_t entrySize,
            uint16_t vectorOffset, uint16_t landAdjust) -> void
        {
            Address offset{0};
            for (uint16_t count{0}; count < entryCount; ++count)
            {
                Address assemblyOffset{AddressToAssemblyOffset(tableAddress + offset)};
                offset += entrySize;
                Address vectorAddress{
                    static_cast<Address>(
                        ((_assembly[assemblyOffset + vectorOffset + 1] << 8) |
                         _assembly[assemblyOffset + vectorOffset]))};
                if (vectorAddress >= GetOriginAddress())
                    switch (landAdjust)
                    {
                        case 0: DeclareNormalVectorTable(vectorAddress, 1); break;
                        case 1: DeclareMinusOneVectorTable(vectorAddress, 1); break;
                        default: assert(false);
                    }
            }
        }
    };
    for (const auto &table: _indirectVectorTables)
    {
        const Address &tableAddress{table.first};
        const uint16_t &entryCount{table.second};
        ftor(tableAddress, entryCount, sizeof(Address), 0, 0);
    }
    for (const auto &table: _keyedIndirectVectorTables)
    {
        const Address &tableAddress{table.first};
        const uint16_t &entryCount{table.second};
        ftor(tableAddress, entryCount, sizeof(Opcode) + sizeof(Address), 1, 0);
    }
    for (const auto &table: _keyedIndirectMinusOneVectorTables)
    {
        const Address &tableAddress{table.first};
        const uint16_t &entryCount{table.second};
        ftor(tableAddress, entryCount, sizeof(Opcode) + sizeof(Address), 1, 1);
    }
}

void
Analyzer::AddVectorLedges ()
{
    auto ftor{
        [this] (const Address &tableAddress, const uint16_t &entryCount, uint16_t entrySize,
            uint16_t vectorOffset, uint16_t splitOffset, uint16_t landAdjust) -> void
        {
            Address offset{0};
            for (uint16_t count{0}; count < entryCount; ++count)
            {
                Address assemblyOffset{AddressToAssemblyOffset(tableAddress + offset)};
                offset += entrySize;
                Address landAddress{
                    static_cast<Address>(
                        ((_assembly[assemblyOffset + vectorOffset + splitOffset + 1] << 8) |
                         _assembly[assemblyOffset + vectorOffset]) +
                        landAdjust)};
                if (landAddress >= GetOriginAddress())
                    AddLand(landAddress, Segment::ST_CodeKnown);
            }
        }
    };
    for (const auto &table: _normalVectorTables)
    {
        const Address &tableAddress{table.first};
        const uint16_t &entryCount{table.second};
        ftor(tableAddress, entryCount, sizeof(Address), 0, 0, 0);
    }
    for (const auto &table: _minusOneVectorTables)
    {
        const Address &tableAddress{table.first};
        const uint16_t &entryCount{table.second};
        ftor(tableAddress, entryCount, sizeof(Address), 0, 0, 1);
    }
    for (const auto &table: _keyedVectorTables)
    {
        const Address &tableAddress{table.first};
        const uint16_t &entryCount{table.second};
        ftor(tableAddress, entryCount, sizeof(Opcode) + sizeof(Address), 1, 0, 0);
    }
    for (const auto &table: _splitVectorTables)
    {
        const Address &tableAddress{table.first};
        const uint16_t &entryCount{table.second};
        ftor(tableAddress, entryCount, sizeof(Address) / 2, 0, static_cast<uint16_t>(entryCount - 1), 0);
    }
}

void
Analyzer::InitializeAssembly ()
{
    const auto originAddress{GetOriginAddress()};
    if (originAddress + _assemblySize > kMaxAssemblySize)
    {
        std::ostringstream text;
        text << "Origin address ($" <<
            std::hex << std::uppercase << std::setfill('0') << originAddress <<
            ") + object size ($" <<
            std::setfill('0') << _assemblySize <<
            ") exceeds maximum address ($" <<
            std::setfill('0') << kMaxAssemblySize - 1 << ')' <<
            " -- is the origin address set correctly? (see -o option)";
        throw Hac65Exception(text.str());
    }

    _endAddress = originAddress + static_cast<Address>(_assemblySize - 1);

    // Collect vector addresses:
    {
        auto ftor{
            [this] (const std::pair<Address, uint16_t> &pair, const uint16_t &vectorSize) -> void
            {
                const Address &tableAddress{pair.first};
                const uint16_t &vectorCount{pair.second};
                const uint16_t &octetCount{static_cast<uint16_t>(vectorCount * vectorSize)};
                for (Address offset{0}; offset < octetCount; ++offset)
                    _allVectorAddresses.insert(tableAddress + offset);
            }};
        std::for_each(std::begin(_jumpVectorTables), std::end(_jumpVectorTables),
            [this, ftor] (const std::pair<Address, uint16_t> &pair)
            { ftor(pair, 3); });
        std::for_each(std::begin(_keyedVectorTables), std::end(_keyedVectorTables),
            [this, ftor] (const std::pair<Address, uint16_t> &pair)
            { ftor(pair, 3); });
        std::for_each(std::begin(_keyedIndirectVectorTables), std::end(_keyedIndirectVectorTables),
            [this, ftor] (const std::pair<Address, uint16_t> &pair)
            { ftor(pair, 3); });
        std::for_each(std::begin(_keyedIndirectMinusOneVectorTables), std::end(_keyedIndirectMinusOneVectorTables),
            [this, ftor] (const std::pair<Address, uint16_t> &pair)
            { ftor(pair, 3); });
        std::for_each(std::begin(_splitVectorTables), std::end(_splitVectorTables),
            [this, ftor] (const std::pair<Address, uint16_t> &pair)
            { ftor(pair, 2); });
        std::for_each(std::begin(_minusOneVectorTables), std::end(_minusOneVectorTables),
            [this, ftor] (const std::pair<Address, uint16_t> &pair)
            { ftor(pair, 2); });
        std::for_each(std::begin(_normalVectorTables), std::end(_normalVectorTables),
            [this, ftor] (const std::pair<Address, uint16_t> &pair)
            { ftor(pair, 2); });
        std::for_each(std::begin(_indirectVectorTables), std::end(_indirectVectorTables),
            [this, ftor] (const std::pair<Address, uint16_t> &pair)
            { ftor(pair, 2); });
    }
}

void
Analyzer::InitializeLedges ()
{
    AddVectorIndirections();

    AddVectorLedges();

    AddJumpVectorLedges();
}

void
Analyzer::InferSegments ()
{
    InitializeSegments();

    auto landsItor{std::begin(_lands)};
    assert(landsItor != std::end(_lands));
    auto leapsItor{std::begin(_leaps)};
    assert(leapsItor != std::end(_leaps));

    // Infer code segments:
    const auto originAddress{GetOriginAddress()};
    Address startAddress{originAddress};
    Address endAddress{startAddress};
    while (startAddress <= _endAddress && landsItor != end(_lands) && leapsItor != end(_leaps))
    {
        Segment::Type segmentType{Segment::ST__Unknown};
        do
        {
            segmentType = landsItor->_type;
            startAddress = landsItor->_address;
            ++landsItor;
        }
        while (
            startAddress != originAddress &&
            startAddress <= endAddress &&
            landsItor != end(_lands));
        do
        {
            endAddress = *leapsItor++;
        }
        while (
            endAddress < startAddress &&
            leapsItor != end(_leaps));

        if (startAddress <= endAddress && endAddress <= _endAddress)
            AddSegment(startAddress, {segmentType, startAddress, endAddress});
    }

    // Segment non-jump vector tables:
    for (const auto &pair: _normalVectorTables)
        AddSegment(
            pair.first,
            {Segment::ST_DataKnown, pair.first, static_cast<Address>(pair.first + pair.second * sizeof(Address) - 1)});
    for (const auto &pair: _indirectVectorTables)
        AddSegment(
            pair.first,
            {Segment::ST_DataKnown, pair.first, static_cast<Address>(pair.first + pair.second * sizeof(Address) - 1)});
    for (const auto &pair: _keyedVectorTables)
        AddSegment(
            pair.first,
            {
                Segment::ST_DataKnown,
                pair.first,
                static_cast<Address>(pair.first + pair.second * (sizeof(Opcode) + sizeof(Address)) - 1)
            });
    for (const auto &pair: _keyedIndirectVectorTables)
        AddSegment(
            pair.first,
            {
                Segment::ST_DataKnown,
                pair.first,
                static_cast<Address>(pair.first + pair.second * (sizeof(Opcode) + sizeof(Address)) - 1)
            });
    for (const auto &pair: _keyedIndirectMinusOneVectorTables)
        AddSegment(
            pair.first,
            {
                Segment::ST_DataKnown,
                pair.first,
                static_cast<Address>(pair.first + pair.second * (sizeof(Opcode) + sizeof(Address)) - 1)
            });
    for (const auto &pair: _minusOneVectorTables)
        AddSegment(
            pair.first,
            {Segment::ST_DataKnown, pair.first, static_cast<Address>(pair.first + pair.second * sizeof(Address) - 1)});
    for (const auto &pair: _splitVectorTables)
        AddSegment(
            pair.first,
            {Segment::ST_DataKnown, pair.first, static_cast<Address>(pair.first + pair.second * sizeof(Address) - 1)});

    // Infer remaining data segments:
    startAddress = originAddress;
    for (const auto &pair: _segments)
    {
        const auto &segmentAddress{pair.first};
        const auto &segment{pair.second};
        if (startAddress < segmentAddress)
        {
            endAddress = segment._startAddress - static_cast<Address>(1);
            if (endAddress <= _endAddress)
            {
                const auto labelOpt{LookupLabel(startAddress, std::nullopt)};
                const Segment::Type segmentType{labelOpt ? Segment::ST_DataKnown : Segment::ST_DataInferred};
                AddSegment(startAddress, {segmentType, startAddress, endAddress});
            }
        }
        startAddress = segment._endAddress + static_cast<Address>(1);
    }
    if (startAddress != 0 /* overflow */ && startAddress < _endAddress)
        AddSegment(startAddress, {Segment::ST_DataInferred, startAddress, _endAddress});
}

bool
Analyzer::InferLedges1 ()
{
    const auto oldLeapsCount{_leaps.size()};

    auto legalHandler{
        [this] (const Address &address, const Instruction &instruction) -> bool
        {
            bool result{false};    // instruction leap discovered?

            const AddressMode &addressMode{instruction._opcodeInfo._addressMode};
            const AddressModeInfo &addressModeInfo{kAddressModeInfos.at(addressMode)};
            switch (instruction._opcodeInfo._mnemonic)
            {
                case M_BCC: case M_BCS: case M_BEQ: case M_BNE: case M_BMI: case M_BPL: case M_BVC: case M_BVS:
                    {
                        auto offset{static_cast<int8_t>(instruction._operand)};
                        AddLand(
                            address + addressModeInfo._operandSize + static_cast<uint16_t>(1) + offset,
                            Segment::ST_CodeInferred);
                    }
                    break;
                case M_BRK:
                    AddLeap(address);
                    result = true;
                    break;
                case M_JMP:
                    AddLeap(address + addressModeInfo._operandSize);
                    if (addressMode != AM_Indirect)
                    {
                        AddLand(instruction._operand, Segment::ST_CodeInferred);
                    }
                    result = true;
                    break;
                case M_JSR:
                    AddLand(instruction._operand, Segment::ST_CodeInferred);
                    break;
                case M_RTI:
                case M_RTS:
                    AddLeap(address + addressModeInfo._operandSize);
                    result = true;
                    break;

                default: break;
            }

            return result;
        }};
    auto illegalHandler{std::function<void (const Address &address, const Opcode &opcode)>()};
    for (const auto &land: _lands)
        DecodeInstructions(land._address, _endAddress, legalHandler, illegalHandler);

    return _leaps.size() > oldLeapsCount;
}

bool
Analyzer::InferLedges2 ()
{
    const auto oldLandsCount{_lands.size()};

    auto legalHandler{
        [this] (const Address &address, const Instruction &instruction) -> bool
        {
            const AddressMode &addressMode{instruction._opcodeInfo._addressMode};
            const AddressModeInfo &addressModeInfo{kAddressModeInfos.at(addressMode)};
            switch (instruction._opcodeInfo._mnemonic)
            {
                case M_BCC: case M_BCS: case M_BEQ: case M_BNE: case M_BMI: case M_BPL: case M_BVC: case M_BVS:
                    {
                        auto offset{static_cast<int8_t>(instruction._operand)};
                        AddLand(
                            address + addressModeInfo._operandSize + static_cast<uint16_t>(1) + offset,
                            Segment::ST_CodeInferred);
                    }
                    break;
                case M_BRK:
                    AddLeap(address);
                    break;
                case M_JMP:
                    AddLeap(address + addressModeInfo._operandSize);
                    if (addressMode != AM_Indirect)
                    {
                        AddLand(instruction._operand, Segment::ST_CodeInferred);
                    }
                    break;
                case M_JSR:
                    AddLand(instruction._operand, Segment::ST_CodeInferred);
                    break;
                case M_RTI:
                case M_RTS:
                    AddLeap(address + addressModeInfo._operandSize);
                    break;

                default: break;
            }

            return false;
        }};
    auto illegalHandler{std::function<void (const Address &address, const Opcode &opcode)>()};
    for (const auto &pair: _segments)
    {
        const auto &segment{pair.second};
        if (segment.IsCode())
            DecodeInstructions(segment._startAddress, segment._endAddress, legalHandler, illegalHandler);
    }

    return _lands.size() > oldLandsCount;
}

uint16_t
Analyzer::DecodeInstructions (
    const Address &startAddress,
    const Address &endAddress,
    const std::function<bool (Address, Instruction)> &legalHandler,
    const std::function<void (Address, Opcode)> &illegalHandler) const
{
    uint16_t illegalCount{0};

    const auto originAddress{GetOriginAddress()};
    uint16_t startPosition{static_cast<uint16_t>(startAddress - originAddress)};
    uint16_t endPosition{static_cast<uint16_t>(endAddress - originAddress)};

    for (uint16_t position{startPosition}; position <= endPosition;)
    {
        const Address address{static_cast<Address>(originAddress + position)};

        if (address >= kNmiVector)
            break;

        const Opcode opcode{_assembly[position]};
        if (kOpcodeInfos.find(opcode) == kOpcodeInfos.end())
        {
            if (illegalHandler)
                illegalHandler(address, opcode);
            ++illegalCount;
        }
        else
        {
            Operand operand{0};
            const OpcodeInfo &opcodeInfo{kOpcodeInfos.at(opcode)};
            const AddressMode &addressMode{opcodeInfo._addressMode};
            const AddressModeInfo &addressModeInfo{kAddressModeInfos.at(addressMode)};
            switch (addressModeInfo._operandSize)
            {
                case 0: break;

                case 1:
                    operand = _assembly[position + 1];
                    break;

                case 2:
                    operand = _assembly[position + 1];
                    operand |= (_assembly[position + 2] << 8);
                    break;

                default: assert(false);
            }

            if (legalHandler(address, {opcode, opcodeInfo, operand}))
                break;

            position += addressModeInfo._operandSize;
        }
        position += (sizeof opcode);
    }

    return illegalCount;
}

void
Analyzer::ExtractCode ()
{
    auto legalHandler{
        [this] (const Address &address, const Instruction &instruction) -> bool
        {
            AddInstruction(address, instruction);
            return false;
        }};
    auto illegalHandler{
        [this] (const Address &address, const Opcode &opcode) -> void
        {
            AddIllegal(address, opcode);
        }};
    for (const auto pair: _segments)
    {
        const auto &segment{pair.second};
        if (segment.IsCode())
            DecodeInstructions(segment._startAddress, segment._endAddress, legalHandler, illegalHandler);
    }
}

void
Analyzer::ExtractData ()
{
    // Assume illegal instructions occupy data segments only:
    for (const auto &pair: _illegals)
    {
        for (auto itor{std::rbegin(_segments)}; itor != std::rend(_segments); ++itor)
        {
            const auto &segmentAddress{itor->first};
            auto &segment{itor->second};
            const auto &illegalAddress{pair.first};
            if (segmentAddress <= illegalAddress)
            {
                segment._type = Segment::ST_DataInferred;
                break;
            }
        }
    }

    for (auto itor{std::begin(_segments)}; itor != std::end(_segments);)
    {
        auto &segment{itor->second};
        if (segment.IsData())
        {
            // Merge adjacent data segments of the same type:
            auto mergingItor{itor};
            ++mergingItor;
            while (mergingItor != end(_segments) && mergingItor->second._type == segment._type)
            {
                segment._endAddress = mergingItor->second._endAddress;
                mergingItor = _segments.erase(mergingItor);
            }

            // Collect data octets:
            Address address{segment._startAddress};
            do
            {
                AddData(address, _assembly[address - GetOriginAddress()]);
            }
            while (address++ < segment._endAddress);

            itor = mergingItor;
        }
        else
            ++itor;
    }
}

void
Analyzer::ExtractDarkCode ()
{
    auto prevItor{std::begin(_segments)};
    for (auto itor{prevItor}; itor != std::end(_segments); ++itor)
    {
        bool hasCodePredecessor{(prevItor == std::begin(_segments)) ? true : prevItor->second.IsCode()};
        auto nextItor{itor};
        ++nextItor;
        bool hasCodeSuccessor{(nextItor == std::end(_segments)) ? true : nextItor->second.IsCode()};
        auto &segment{itor->second};
        if ((segment._type == Segment::ST_DataInferred) &&
            (hasCodePredecessor || hasCodeSuccessor) &&
            (segment._endAddress - segment._startAddress > 1) &&
            !SegmentHasVectors(segment))
        {
            uint16_t illegalCount{
                DecodeInstructions(
                    segment._startAddress,
                    segment._endAddress,
                    [] (const Address &address, const Instruction &instruction) -> bool
                    { return false; },
                    std::function<void (const Address &address, const Opcode &opcode)>())};

            if (illegalCount == 0)
            {
                segment._type = Segment::ST_CodeDark;
                DecodeInstructions(
                    segment._startAddress,
                    segment._endAddress,
                    [this] (const Address &address, const Instruction &instruction) -> bool
                    {
                        AddInstruction(address, instruction);
                        return false;
                    },
                    [this] (const Address &address, const Opcode &opcode) -> void
                    {
                        AddIllegal(address, opcode);
                    });
            }
        }
        prevItor = itor;
    }
}

MD5
Analyzer::FingerprintCodeSegment (const Segment &segment) const
{
    std::vector<Octet> filtered;
    auto legalHandler{
        [this, &filtered] (const Address &address, const Instruction &instruction) -> bool
        {
            filtered.push_back(instruction._opcode);
            switch (instruction._opcodeInfo._addressMode)
            {
                case AM_Accumulator:
                case AM_Implied:
                    break;
                case AM_IndirectX:
                case AM_IndirectY:
                case AM_ZeroPage:
                case AM_ZeroPageX:
                case AM_ZeroPageY:
                    filtered.push_back(0);
                    break;
                case AM_Absolute:
                case AM_AbsoluteX:
                case AM_AbsoluteY:
                case AM_Indirect:
                    filtered.push_back(0);
                    filtered.push_back(0);
                    break;
                case AM_Immediate:
                case AM_Relative:
                    filtered.push_back(static_cast<Octet>(instruction._operand & 0xFF));
                    break;
                default:
                    break;
            }
            return false;
        }};
    auto illegalHandler{std::function<void (const Address &address, const Opcode &opcode)>()};
    DecodeInstructions(segment._startAddress, segment._endAddress, legalHandler, illegalHandler);

    MD5 result;
    result.update(filtered.data(), static_cast<MD5::size_type>(filtered.size()));
    result.finalize();
    return result;
}

MD5
Analyzer::FingerprintDataSegment (const Segment &segment) const
{
    MD5 result;
    MD5::size_type segmentLength{static_cast<MD5::size_type>(segment._endAddress) - segment._startAddress + 1};
    auto originAddress{GetOriginAddress()};
    result.update(_assembly.data() + segment._startAddress - originAddress, segmentLength);
    result.finalize();
    return result;
}

const std::optional<std::vector<std::string>>
Analyzer::LookupEquate (const uint16_t &value) const
{
    std::optional<std::vector<std::string>> resultOpt;
    std::vector<std::string> equates;
    auto range{_equates.equal_range(value)};
    for (auto itor{range.first}; itor != range.second; ++itor)
    {
        const auto &equate{itor->second};
        equates.push_back(equate);
    }
    if (!equates.empty())
        resultOpt = equates;
    return resultOpt;
}

const std::optional<std::string>
Analyzer::LookupLabel (const Address &address, std::optional<MemoryOperation> memoryOperationOpt) const
{
    std::optional<std::string> resultOpt;
    auto memoryOperation{memoryOperationOpt.value_or(MO__Unknown)};
    switch (memoryOperation)
    {
        case MO_None:
        case MO__Unknown:
            {
                auto itor{_codeLabels.find(address)};
                if (itor != end(_codeLabels))
                    resultOpt = itor->second;
            }
            break;
        default:
            break;
    }
    if (!resultOpt)
    {
        switch (memoryOperation)
        {
            case MO_None:
            case MO_Read:
            case MO_Write:
            case MO_Both:
            case MO__Unknown:
                {
                    auto range{_dataLabels.equal_range(address)};
                    for (auto itor{range.first}; itor != range.second; ++itor)
                    {
                        auto label{itor->second};
                        const auto lastChar{label[label.size() - 1]};
                        if (lastChar == '<' || lastChar == '>')
                            label.pop_back();
                        resultOpt = label;
                        if ((lastChar == '<' && (memoryOperation == MO_Read || memoryOperation == MO_Both)) ||
                            (lastChar == '>' && (memoryOperation == MO_Write)))
                            break;
                    }
                }
                break;
            default: break;
        }
    }

    return resultOpt;
}

void
Analyzer::Analyze ()
{
    InitializeAssembly();

    InitializeLedges();
    if (InferLedges1())
    {
        InferSegments();
        while (InferLedges2())
            InferSegments();
    }

    if (_segments.empty())
    {
        std::string text {"Curiously, no valid segments were discovered"
                          " -- is the origin address set correctly? (see -o option)"};
        throw Hac65Exception(text);
    }

    ExtractCode();
    if (_isIlluminating)
        ExtractDarkCode();
    ExtractData();
}

}

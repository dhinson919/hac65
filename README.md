# *HAC/65 - The 6502 Inferencing Disassembler*

- [What is it?](#what-is-it)
- [What can I do with it?](#what-can-i-do-with-it)
- [How does it work?](#how-does-it-work)
- [How do I get started?](#how-do-i-get-started)
    - [Building HAC/65](#building-hac65)
    - [Example session](#example-session)
- [The Big Leagues](#the-big-leagues)
- [FAQ (yet to be asked)](#faq-yet-to-be-asked)

## What is it?
HAC/65 is yet another addition to the surfeit of 6502 disassemblers available to hobbyists and computer historians
(http://6502.org/tools/asm/).  But there are a few notable features that set it apart from the pack:
- It has some smarts.  Given some 6502 object code it will study it to determine which segments are code and which are
data and fingerprint them so they can be easily spotted in other object code.  It can even illuminate "dark code"
lurking in a binary -- mysteriously uncalled code segments that may be of interest to historians, bug-hunters and
conspiracy theorists.
- It is extensible.  You can make it smarter by supplying extra knowledge in the form of stackable architecture overlays
-- data files that let you assist the tool with known symbols, data structures locations, and program counter targets.
This enables a powerful, iterative reverse-engineering workflow for researchers as well as providing new opportunities
for automating the jobs of revision comparative analysis and historical assembly code listing re-documentation.
- It's implemented as a single Modern C++ executable with no additonal runtime dependencies so it is fast, small, and
future-proof. Its modular design allows the core analyzer component to be easily embedded into other native code
applications.
- It's hosted on Github, not some fly-by-night domain that you can never remember. So it will be standing by here
waiting for you day or night until the sun explodes or you finally lose interest in old 6502 hardware, whichever comes
first. 
- It's new, and newer is always better, right?

## What can I do with it?
It's main purpose is to serve as a tool for exploring poorly or completely undocumented 6502 object code at the
subroutine level. Despite not being a new pastime among legacy computer hardware enthusiasts the author grew frustrated
with the lack of good tools to do rigorous comparative studies of legacy ROM code revisions and product evolution. And
while he found decent tools for basic disassembly, none allowed a user to iteratively refine the results as knowledge of
a particular product was gained. The latter feature is especially important for analyzing object code with limited
access to original source code and when the most useful information comes from code snippets in old magazine articles
and fragments of long-dead BBS and Internet forum conversations.

HAC/65 is an attempt to address these needs by producing three basic reports:
- A segmentation report shows the individual contiguous groupings of both instructions and non-instruction data bytes.
Instruction (code) segments typically represent individual subroutines. Once the purpose of a particular subroutine is
determined it can be assigned a label which is then shown by subsequent disassemblies in called and caller code. Data
segments typically represent one more more data structures and they too can be assigned labels and declared as such
to the analyzer which may help it discover additional code segments.

- A segment fingerprint report lists information about the segments ordered by fingerprint ID (hash code).  Segments
with the same fingerprint are likely candidates for being duplicate code within the same object code or across different
object code files.  This is useful for spotting new instruction sequences across ROM revisions, for example, where
older segments may have been relocated within the address space but otherwise unaltered.

- A disassembly report produces a more conventional disassembler output using a simple listing format that works well
for use with differencing tools to spot specific differences in instructions or data across object code files. Clever
users could even automate the translation of the listing into source code for actual assemblers with relative ease.
    
## How does it work?
There are many different techniques that can be used to disassemble object code. The author chose code ledge analysis
which, while not as thorough as say control flow or simulation analysis, is relatively simple and produces sufficient
results thanks to the limited complexity of 6502 architecture and applications.

In a nutshell, the analyzer tries to infer contiguous instruction segments by looking for program counter
"landing-edges" and "leaping-edges", aka ledges.  It uses an iterative process of identifying ledges and then analyzing
the instructions between them to find new ledges.  Once all ledges have been identified then, in theory, all code
segments have been identified and therefore any segments left over must be data segments. However there is the
possibility that some of the leftover segments could actually be unreachable code segments, aka dark code.  If the user
chooses, those segments can be further analyzed using some simple heuristics to determine if they are likely code or
likely data and treated as such.

## How do I get started?
First it should be understood that the tool is meant for the advanced hobbyist with multi-platform skills. The author
has attempted to construct a quality product, for his personal machinations if for nobody else, but there has been
little consideration for making it accessible to a broad audience and there likely won't be. He simply doesn't have the
time! However, it is fully frontally exposed here on Github for anyone to use and integrate into there own projects with
a very permissive license and no strings attached. The author is motivated purely by the desire to help preserve
knowledge of legacy 6502 hardware of all kinds and would be happy to assist similar efforts.

Currently, to use it you will need:
- A 64-bit Linux distro. It has not yet been ported to Windows, Mac or anything else.
- The ability to edit files on Linux if you want to add or modify architecture overlay files.

You can get started right away by
[downloading just the pre-built executable](https://github.com/dhinson919/hac65/raw/master/build/amd64/release/hac65).

To build it you will need:
- A recent 64-bit Linux distro. It was developed and tested on Ubuntu 18.04.1 LTS "bionic".
- git (or compatible), cmake and g++ 7.1 (minimum).

### Building HAC/65

1. Ensure you have the required prerequisites:
    ```commandline
    $ sudo apt-get install git cmake g++
    ```

2. Clone the project:
    ```commandline
    $ git clone https://github.com/dhinson919/hac65.git
    ```
    
3. Make the executable:
    ```commandline
    $ cd hac65
    $ cmake .
    $ make
    ```
 
4. The executable `hac65` will be built into the current working directory.
 
### Example session
The following example session illustrates features and uses of the tool.
 
First, let's run the tool without any args:
 
```commandline
$ ./hac65
Error: usage: hac65 [options] object-file
Options:
  -h               Display this information
  -v               Display version
  -S <digits>      Starting position within object
  -E <digits>      Ending position within object
  -A <aro-name>    Top architecture overlay
  -o <digits>      Origin address
  -i               Illuminate dark code
  -R [sfdo]        Reporting options
                     s = segments
                     f = segment fingerprints
                     d = disassembly
                     o = overlays
```    
As you can see it could not continue because of missing command line arguments.  Specifically, you must at least supply
the path to an object file to analyze. The object file can be located anywhere but if you intend to use architecture
overlay files (.aro, see below) they must be located in the tool's working directory. 

The project distribution comes with a few sample ROMs in the `rom/` directory:
```commandline
$ ls -l rom
total 40
drwxr-xr-x 2 hac65er hac65er  4096 Nov  4 13:53 ./
drwxr-xr-x 6 hac65er hac65er  4096 Nov  4 23:41 ../
-rw-r--r-- 1 hac65er hac65er  4096 Nov  4 13:53 1050-FLOPOS.rom
-rw-r--r-- 1 hac65er hac65er  4096 Nov  4 13:53 1050-revK.rom
-rw-r--r-- 1 hac65er hac65er 10240 Nov  4 13:53 800antsc.rom
-rw-r--r-- 1 hac65er hac65er 10240 Nov  4 13:53 800apal.rom
```
These are commonly available ROM images for Atari 400/800 OS "A" systems (NTSC and PAL) and Atari 1050 floppy drives.
Both are 6502 architecture systems so they are object file candidates. We'll use them in the following examples.

Let's try to disassemble the 1050-revK revision and see what happens:
```commandline
$ hac65 rom/1050-revK.rom
Error: encountered an out-of-object address ($FFFA) -- is the origin address set correctly? (see -o option)
```
HAC/65 will always try to be polite and helpful even when it knows we've done something stupid. In this case we've
failed to supply a value for the disassembly origin. Why is this necessary? Notice in the file listing that
1050-revK.rom is 4k bytes in size. But as everybody knows the 6502 has a 64k address space. When provided
an object file HAC/65 will, unless told otherwise, assume that the object code had an original starting address of
$0000. That would mean the highest object address would be $1000 (4k). There would not be a problem if that was in fact
true, but in this case the analyzer been asked to resolve the address $FFFA which is well outside of that address range.
What's going on?

To explain this we have to digress for a moment. As mentioned earlier one feature that sets HAC/65 apart from
other disassemblers is its use of architecture overlays. These are stackable sets of metadata used to describe a
portion of the 6502's address space. They are typically supplied by files with the .aro extension and the top-most one
is specified on the command line with the -A option. However there is a default overlay built-in to the tool named
"Builtin_MOS6502" that will be used when no other top overlay is specified. In overlay format it looks like this:
```commandline
# Builtin_MOS6502:
{
  "structures": {
    "normal_vector_tables": {
      "$FFFA": 3
    }
  }
}
```
Students of the 6502 will recognize address $FFFA as the starting location of the 3 machine vectors for
NMI, reset and IRQ. These are especially important to the analyzer because they supply the most fundamental code ledge knowledge.
To wit, every 6502 application must at least load the reset vector with the location of a valid code segment. That's all
the analyzer needs to begin its cycles of discovery.

This overlay declares a vector table (a kind of data structure) containing 3 elements starting at location
$FFFA. Since that address is well beyond the configured top address of $1000 the analyzer cannot continue and rightfully
complains.

The fix is to simply follow the advice of the error message and supply the tool with a valid origin address. Since we
happen to know that 1050 ROM images reside at the very top of the machine address space we can calculate that the
correct origin address should be ($FFFF + 1 - $1000) or $F000. Let's supply that information now and see what happens:
```commandline
$ hac65 -o '$F000' rom/1050-revK.rom
HAC/65 v0.5 6502 Inferencing Disassembler [run:Mon Nov  5 05:23:57 2018]
hac65 -o $F000 rom/1050-revK.rom[md5:5acf59fff75d36a079771b34d7c7d349]

Architecture Overlays:
    Builtin_MOS6502

Segments Report
---------------
Assembly size (bytes) : 4096
Segments (count)      : 154
  Known Code          : 2
  Inferred Code       : 140
  Dark Code           : 0
  Known Data          : 1
  Inferred Data       : 11

                                 *= $F000

#144 F000-F012 data_inferred a3decbada7dfa4fec71e9d5e84178e72
FB F7 EF DF 57 52 50 57 53 21 22 23 24 33 32 34
31 FF 00

#1 F013-F09D code_known c29cd090ca505a926a8fe6aa65934894
F013  D8                         CLD 
F014  A2 FF                      LDX #$FF     
F016  9A                         TXS 
F017  A9 3C                      LDA #$3C     
F019  8D 81 02                   STA $0281
F01C  A9 38                      LDA #$38     
F01E  8D 80 02                   STA $0280

[edited for brevity]

FFCE  0D 82 02                   ORA $0282
FFD1  8D 82 02                   STA $0282
FFD4  4C A0 FB                   JMP $FBA0

#154 FFD7-FFF9 data_inferred b6e1cebc1f9a86d0f90a80fa26ac4903
AA AA AA AA AA AA AA AA AA BA CB 44 BE 07 61 C4
C0 F4 F5 F6 F6 F7 F8 FA FE AA AA AA AA AA AA AA
AA AA 4B

#143 FFFA-FFFF data_known 1beed77361cd09a0cc066c2bbc77dd88
04 1A 13 F0 C9 FF
```
Result! What we see is a segments report, the default when no other ones are specified.

There are a few things worth pointing out about this:
- Notice that the origin address is supplied in single-quotes: `'$F000'`. Numerical digits can be supplied to HAC/65 in
a number of different ways, including hexadecimal prefixed with '$' as is common in the 6502 universe. However the Linux
shell has it's own conflicting interpretation of what `$F000` means on a command line so we must escape it to avoid
trouble. The address is displayed later in listings using the common assembler format `*= $F000`.
- The top few lines are a header that precedes every report or set of reports. Among other things it contains the
command line arguments used to invoke the tool which can sometimes be a useful reminder when interpreting the results.
- Builtin_MOS6502 is mentioned in the header's overlay listing. If other overlays were stacked up they would be listed
here also.
- The segments report has a useful summary of segment category counts. Currently, the inferred segments greatly
outnumber the known segments because the analyzer doesn't yet have much knowledge about the object's architecture. By
contributing additional overlays the balance can be shifted to the point where no inferencing is required at all if
desired, such as for annotation completeness.
- Each segment descripition begins with a one-line summary showing its numerical identifier, its address range, its
segment category, and its MD5 fingerprint. The identifier happens to also be the order that the segment was discovered
by the analyzer. That can be useful information for understanding the inner workings of the analyzer should
you ever suspect conflicts as the amount of overlay knowledge grows.
- The segments start at address $F000 and end at $FFFF. Indeed, location $F013 marks the beginning of one of the
two "known" code segments and $FFFA the beginning of the sole known data segment. That is of course the
set of 3 machine vectors mentioned earlier. Now notice the value of the middle vector address within the last segment:
$F013. Coincedence? Not at all. Congratulations, you've just identified your first code segment to be the reset vector
subroutine! That code segment is described as "known" because the analyzer is hip to the fact that its sole known vector
table also represents pointers to code.

Now that we've discovered the reset subroutine, let's encapsulate that knowledge in a new architecture overlay:
```commandline
$ vi Example.aro

# Discovered knowledge about 1050 revK.
@include "Builtin_MOS6502"
{
    "origin": "$F000",
    "code_labels":
    {
        "RESET": "$F013"
    }
}
```
Notice the following:
- The format of the overlay is modified JSON. Enhancements to standard JSON include to-end-of-line comments, indicated
with '#', and preprocessing directives indicated with '@'. Directives must precede the initial '{' of the JSON object.
- The @include directive allows you to specify additional overlays to be added to the overlay stack. The final stack
will be the recursive mix-in of all specified overlays in the order that they were specified during overlay traversal.
In this case, the bottom of the stack will contain the contributions from Builtin_MOS6502 overlayed with the contents of
this file. This means, in most cases, prior values are overwritten by subsequent values.
- The JSON portion contains top-level elements which themselves may contain sub-elements.
- The top-level element "origin" can be used to specify the origin address instead of requiring it on the
command line.
- The top-level element "code_labels" is a JSON object whose elements are name/value pairs. The name must be
unique. The value must be either in normal JSON number form or in "HAC/65 digits" string form. For example, HAC/65
supports $-prefixed addresses commonly used by 6502 assemblers and found in their listings.

Now when we run it we can leave out the -o argument but we must add "-AExample" to indicate the custom overlay file:
```commandline
$ hac65 -AExample rom/1050-revK.rom
HAC/65 v0.5 6502 Inferencing Disassembler [run:Tue Nov  5 15:12:53 2018]
hac65 -AExample rom/1050-revK.rom[md5:5acf59fff75d36a079771b34d7c7d349]

Architecture Overlays:
    Example
    Builtin_MOS6502

Segments Report
---------------
Assembly size (bytes) : 4096
Segments (count)      : 154
  Known Code          : 2
  Inferred Code       : 140
  Dark Code           : 0
  Known Data          : 1
  Inferred Data       : 11

                                 *= $F000

#150 F000-F012 data_inferred a3decbada7dfa4fec71e9d5e84178e72
FB F7 EF DF 57 52 50 57 53 21 22 23 24 33 32 34
31 FF 00

#1 F013-F09D code_known c29cd090ca505a926a8fe6aa65934894
F013  D8        RESET            CLD 
F014  A2 FF                      LDX #$FF     
F016  9A                         TXS 
F017  A9 3C                      LDA #$3C     
F019  8D 81 02                   STA $0281
F01C  A9 38                      LDA #$38     
F01E  8D 80 02                   STA $0280

[edited for brevity]
```
To note here are the addition of the Example overlay in the overlays listing and the new "RESET" code label
for address $F013. This is not especially interesting though because as you can see the added knowledge did not change
the segment categorizations. We simply added a name to the first address of an already known code segment.

If we look further down the report we'll see the following segment nearby:
```commandline
#3 F0F7-F101 code_inferred 360b2aec6eb44294ea08367dfeedfd61
F0F7  A9 80                      LDA #$80
F0F9  2D 00 04                   AND $0400
F0FC  AA                         TAX
F0FD  45 9B                      EOR $9B
F0FF  D0 01                      BNE $F102
F101  60                         RTS
```
This is a segment that the analyzer deduced to be code. Let's make it official by assigning it the label
"SOME_SUBROUTINE":
```commandline
$ vi Example.aro

# Discovered knowledge about 1050 revK.
@include "Builtin_MOS6502"
{
    "origin": "$F000",
    "code_labels":
    {
        "RESET": "$F013",
        "SOME_SUBROUTINE": "$F0F7"
    }
}
``` 
Here is the result:
```commandline
$ hac65 -AExample rom/1050-revK.rom
HAC/65 v0.5 6502 Inferencing Disassembler [run:Tue Nov  5 15:18:57 2018]
hac65 -AExample rom/1050-revK.rom[md5:5acf59fff75d36a079771b34d7c7d349]

Architecture Overlays:
    Example
    Builtin_MOS6502

Segments Report
---------------
Assembly size (bytes) : 4096
Segments (count)      : 154
  Known Code          : 3
  Inferred Code       : 139
  Dark Code           : 0
  Known Data          : 1
  Inferred Data       : 11

[edited for brevity]

#3 F0F7-F101 code_known 360b2aec6eb44294ea08367dfeedfd61
F0F7  A9 80     SOME_SUBROUTIN/  LDA #$80
F0F9  2D 00 04                   AND $0400
F0FC  AA                         TAX
F0FD  45 9B                      EOR $9B
F0FF  D0 01                      BNE $F102
F101  60                         RTS
```
As we can see the segment has now been reclassified to "code_known" from "code_inferred".  This is because declaring a
code label does more than just name an address, it also adds the address to the list of code segment landing-edges
which will alter the analyzer's view of the object. We can also see that the label has been abbreviated. This is because
a label is limited to 14 characters.

Now, let's say we happened to know that address $0400 is the memory-mapped address for a control register of the
1050's floppy drive controller chip.  (Which happens to be true.)  And let's say we believe that $80 is the floppy
controller command code for a sector read operation.  (Also true.)  We can impart that knowledge as usual in an overlay:
```commandline
# Discovered knowledge about 1050 revK.
@include "Builtin_MOS6502"
{
    "origin": "$F000",
    "code_labels":
    {
        "RESET": "$F013",
        "SOME_SUBROUTINE": "$F0F7"
    },
    "data_labels":
    {
        "FCNTRL": "$0400"
    },
    "equates":
    {
        "READ": "$80"
    }
}
```
And the result becomes:
```commandline
#3 F0F7-F101 code_known 360b2aec6eb44294ea08367dfeedfd61
F0F7  A9 80     SOME_SUBROUTIN/  LDA #$80     ;READ?
F0F9  2D 00 04                   AND FCNTRL
F0FC  AA                         TAX
F0FD  45 9B                      EOR $9B
F0FF  D0 01                      BNE $F102
F101  60                         RTS
```
Unlike code labels, which identify potential program counter target addresses, data labels identify target addresses of
memory operations but they do not add to the knowledge of code ledges.  Likewise, equates are names for values that
are not addresses at all, such as immediate mode instruction operands.  In this case there's not enough contextual
information to determine whether or not this particular $80 is named by READ or perhaps has some other meaning that
shares the same value, so the equate name is listed as a comment only as a possibility.

Finally, let's say during our research of 1050-related information we're intrigued to learn that there is an 8-element
vector table at location $FFE0 which contains pointers to the handler subroutines for the various Atari serial I/O
commands and we realize it is a potential source of additional code ledges. We can expand the analyzer's knowledge
base with this new information like so:
```commandline
# Discovered knowledge about 1050 revK.
@include "Builtin_MOS6502"
{
    "origin": "$F000",
    "code_labels":
    {
        "RESET": "$F013",
        "SOME_SUBROUTINE": "$F0F7"
    },
    "data_labels":
    {
        "FCNTRL": "$0400"
    },
    "equates":
    {
        "READ": "$80"
    },
    "structures":
    {
        "split_vector_tables":
        {
            "$FFE0": 8  # SIO commands
        }
    }
}
```
Running with this addition results in a significant development: 
```commandline
$ hac65 -AExample rom/1050-revK.rom
HAC/65 v0.5 6502 Inferencing Disassembler [run:Tue Nov  5 15:21:19 2018]
hac65 -AExample rom/1050-revK.rom[md5:5acf59fff75d36a079771b34d7c7d349]

Architecture Overlays:
    Example
    Builtin_MOS6502

Segments Report
---------------
Assembly size (bytes) : 4096
Segments (count)      : 153
  Known Code          : 11
  Inferred Code       : 136
  Dark Code           : 0
  Known Data          : 2
  Inferred Data       : 4
```
As we can see from the segment categories, adding the vector table results in 8 additional known code segments. This
should come as no surprise since the vector table has 8 elements. But the other recategorizations are not so obvious.
For example, the number of inferred data segments was reduced by only 7 and there was a net loss of 1 segment in total.
The explanation for this is left as an exercise for the reader. (Hint: Use a differencing tool against this report and
the prior one.)

## The Big Leagues
The previous example was a simple demonstration of HAC/65's basic capabilities with limited overlay knowledge. But
HAC/65 can easily handle much larger projects. The distribution comes with two notable reference overlays:
- Atari1050RevKAnno - This contains the complete set of annotations from the assembly source code of the
community-contributed 1050 ROM image known as FLOPOS by Michael Pascher (Abbuc-Buch) and W. Derks. Since it is based on
the "K" revision of the 1050 ROM from Atari it can be used to analyze both of the included 1050-revK and 1050-FLOPOS ROM
images. The modifications to the K revision by the two authors can be seen by using a differencing tool against the two
disassembly reports (-Rd option). Below is a sample of the reset vector subroutine of 1050-revK.rom, containing among
other things the notorious 1050 checksum logic:
```commandline
#1 F013-F09D code_known c29cd090ca505a926a8fe6aa65934894
F013  D8        START            CLD 
F014  A2 FF                      LDX #$FF     
F016  9A                         TXS 
F017  A9 3C                      LDA #$3C     
F019  8D 81 02                   STA DDRA
F01C  A9 38                      LDA #$38     
F01E  8D 80 02                   STA DRA
F021  AD 80 02                   LDA DRA
F024  29 3C                      AND #$3C     
F026  C9 38                      CMP #$38     
F028  D0 73                      BNE FAIL
F02A  A9 3D                      LDA #$3D     
F02C  8D 83 02                   STA DDRB
F02F  A9 3D                      LDA #$3D     
F031  8D 82 02                   STA DRB
F034  AD 82 02                   LDA DRB
F037  29 3D                      AND #$3D     
F039  C9 3D                      CMP #$3D     
F03B  D0 60                      BNE FAIL
F03D  A9 D0                      LDA #$D0     
F03F  8D 00 04                   STA FCNTRL
F042  A2 15                      LDX #$15     
F044  CA        DEL1             DEX 
F045  D0 FD                      BNE DEL1
F047  AD 00 04                   LDA FCNTRL
F04A  29 01                      AND #1       
F04C  D0 4F                      BNE FAIL
F04E  A9 55                      LDA #$55     
F050  8D 01 04                   STA TRKREG
F053  8D 02 04                   STA SEKREG
F056  A2 1E                      LDX #$1E     
F058  CA        DEL2             DEX 
F059  D0 FD                      BNE DEL2
F05B  4D 01 04                   EOR TRKREG
F05E  D0 3D                      BNE FAIL
F060  A9 55                      LDA #$55     
F062  4D 02 04                   EOR SEKREG
F065  D0 36                      BNE FAIL
F067  A9 48                      LDA #$48     
F069  8D 00 04                   STA FCNTRL
F06C  A2 28                      LDX #$28     
F06E  20 91 F1                   JSR DELAY1
F071  AD 00 04                   LDA FCNTRL
F074  29 01                      AND #1       
F076  F0 25                      BEQ FAIL
F078  A2 28                      LDX #$28     
F07A  20 91 F1                   JSR DELAY1
F07D  AD 00 04                   LDA FCNTRL
F080  29 01                      AND #1       
F082  D0 19                      BNE FAIL
F084  A9 F0                      LDA #$F0     
F086  85 01                      STA SEKBUF+1
F088  A9 00                      LDA #0       ;SEKBUF?
F08A  85 00                      STA SEKBUF
F08C  18                         CLC 
F08D  A8                         TAY 
F08E  71 00     PCHECK           ADC (SEKBUF),Y
F090  C8                         INY 
F091  D0 FB                      BNE PCHECK
F093  E6 01                      INC SEKBUF+1
F095  D0 F7                      BNE PCHECK
F097  09 00                      ORA #0       ;SEKBUF?
F099  85 00                      STA SEKBUF
F09B  F0 01                      BEQ TSTOK
F09D  00        FAIL             BRK 
```

- Atari800OSA.aro - This contains a large set of annotations from the official 400/800 Operating System revision "A" 
source listing published by Atari. It is compatible with both of the included 800antsc and 800apal ROM images. Below is
a sample of the SETVBL subroutine used to setup the VBLANK interrupts:
```commandline
#121 E912-E93C code_known 079b6b3e32de29f75a8185a14c0cc3cc
E912  0A        SETVBL           ASL A
E913  8D 2D 02                   STA INTEMP
E916  A9 00                      LDA #0       ;B192HI?, CTIMHI?, RADON?, RIRGHI?, WIRGHI?
E918  8D 0E D4                   STA NMIEN
E91B  8A                         TXA 
E91C  AE 2D 02                   LDX INTEMP
E91F  9D 17 02                   STA VIMIRQ+1,X
E922  98                         TYA 
E923  9D 16 02                   STA VIMIRQ,X
E926  A9 40                      LDA #$40     
E928  8D 0E D4                   STA NMIEN
E92B  2C 0F D4                   BIT NMIST
E92E  50 0D                      BVC $E93D
E930  A9 E9                      LDA #$E9     
E932  48                         PHA 
E933  A9 3D                      LDA #$3D     
E935  48                         PHA 
E936  08                         PHP 
E937  48                         PHA 
E938  48                         PHA 
E939  48                         PHA 
E93A  6C 22 02                   JMP (VVBLKI)
```

## FAQ (yet to be asked)
- Why is it called HAC/65?

This should be obvious to anyone who has spent any time with old Atari 8-bit assembler cartridges. It's short for "have
another cigarette".

- Why don't you support platforms for ordinary people, like Windows and Mac and Raspberry Pi?

I would love to but the time I have to dedicate to this project is limited. It takes a lot of effort to support
a multi-platform product properly. At this point in the evolution of the tool I'd prefer to dedicate those spare
resources to improving the core functionality. However there is nothing stopping anyone from cloning this project
and publishing multiple builds. I would be happy to cooperate with such an individual.

- Could you have possibly picked a more difficult to use format for overlay files?

Why yes, I could have used XML! Or some crackpot custom format. I actually considered YAML which is a close cousin of
JSON, but although it is simpler in many ways I still find it not as intuitive as JSON and end up having to refresh my
knowledge of it every time I want to use it. JSON is a more natural fit for developers I believe and odds are if you're
using this tool then you are an experienced developer of some kind.

- Will the tool work with ROM dumps from Commodores or Apples or BBC Micros?

I have not yet tested ROMs sourced from devices other than Ataris but I don't see why they would not work. As long as
they contain 6502 target object code the tool should be able to understand them.  If you decide to make overlays for
those platforms and would like to share them let me know and I'll glad to add them to this collection or reference your
work.

- I would like to contribute some code to your project, will you accept my PR?

Thanks for the offer but I'm not prepared to do justice to contributions at this time. If you have ideas for new
features that would help the community by all means feel free to clone or fork this project and publish them youself.
But if you want to report a defect or request simple improvements please create a new issue on the project home page. 


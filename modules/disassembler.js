(function(root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.Disassembler = factory();
    }
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : global), function() {
    'use strict';

    /**
     * @class Disassembler
     * Wrapper for Capstone.js to decode binary instructions.
     */
    class Disassembler {
        /**
         * @param {Object} capstoneModule - Loaded Capstone.js module instance.
         */
        constructor(capstoneModule) {
            this.cs = capstoneModule;
            
            this.ARCH = {
                ARM: 1,
                ARM64: 2,
                MIPS: 3,
                X86: 4,
                PPC: 5,
                SPARC: 6,
                SYSZ: 7,
                XCORE: 8,
                M68K: 9,
                TMS320C6X: 10,
                M680X: 11,
                EVM: 12
            };
            this.MODE = {
                LITTLE_ENDIAN: 0,
                ARM: 0,
                16: 1 << 1,
                32: 1 << 2,
                64: 1 << 3,
                THUMB: 1 << 4,
                MCLASS: 1 << 5,
                V8: 1 << 6,
                MICRO: 1 << 4,
                MIPS3: 1 << 5,
                MIPS32R6: 1 << 6,
                MIPS2: 1 << 7,
                V9: 1 << 4,
                BIG_ENDIAN: 1 << 31
            };
        }

        isLoaded() {
            return this.cs !== null && this.cs !== undefined;
        }

        getSupportedArchitectures() {
            return [
                { name: 'x86', id: this.ARCH.X86, modes: [{name: '16-bit', id: this.MODE['16']}, {name: '32-bit', id: this.MODE['32']}, {name: '64-bit', id: this.MODE['64']}] },
                { name: 'ARM', id: this.ARCH.ARM, modes: [{name: 'ARM', id: this.MODE.ARM}, {name: 'THUMB', id: this.MODE.THUMB}] },
                { name: 'ARM64 / AArch64', id: this.ARCH.ARM64, modes: [{name: 'ARM', id: this.MODE.ARM}] },
                { name: 'MIPS', id: this.ARCH.MIPS, modes: [{name: 'MIPS32', id: this.MODE['32']}, {name: 'MIPS64', id: this.MODE['64']}, {name: 'MICRO', id: this.MODE.MICRO}] },
                { name: 'PowerPC', id: this.ARCH.PPC, modes: [{name: '32-bit', id: this.MODE['32']}, {name: '64-bit', id: this.MODE['64']}] },
                { name: 'SPARC', id: this.ARCH.SPARC, modes: [{name: '32-bit (V8)', id: this.MODE['32'] | this.MODE.V8}, {name: 'V9', id: this.MODE.V9}] },
                { name: 'SystemZ (s390x)', id: this.ARCH.SYSZ, modes: [{name: 'BIG_ENDIAN', id: this.MODE.BIG_ENDIAN}] },
                { name: 'XCore', id: this.ARCH.XCORE, modes: [{name: 'BIG_ENDIAN', id: this.MODE.BIG_ENDIAN}] },
                { name: 'M68K (Motorola 68000)', id: this.ARCH.M68K, modes: [{name: '32-bit', id: this.MODE['32']}] },
                { name: 'TMS320C6x (DSP)', id: this.ARCH.TMS320C6X, modes: [{name: 'BIG_ENDIAN', id: this.MODE.BIG_ENDIAN}] },
                { name: 'M680x', id: this.ARCH.M680X, modes: [{name: 'Default', id: 0}] },
                { name: 'EVM (Ethereum)', id: this.ARCH.EVM, modes: [{name: 'Default', id: 0}] }
            ];
        }

        disassemble(uint8Array, arch, mode, baseAddress = 0, options = {}) {
            if (!this.isLoaded()) throw new Error("Capstone not loaded");
            if (!(uint8Array instanceof Uint8Array)) throw new Error("Input must be Uint8Array");
            
            const maxInstructions = options.maxInstructions || 1000;
            const offset = options.offset || 0;
            const length = options.length || (uint8Array.length - offset);
            
            const dataToDisasm = uint8Array.subarray(offset, offset + length);
            
            let instructions = [];
            try {
                if (typeof this.cs.Disassembler === 'function') {
                    const disassembler = new this.cs.Disassembler(arch, mode);
                    const insns = disassembler.disasm(dataToDisasm, baseAddress, maxInstructions);
                    
                    instructions = insns.map(insn => ({
                        address: insn.address,
                        addressHex: '0x' + insn.address.toString(16).padStart(8, '0'),
                        bytes: insn.bytes,
                        bytesHex: Array.from(insn.bytes).map(b => b.toString(16).padStart(2, '0')).join(' '),
                        mnemonic: insn.mnemonic,
                        opStr: insn.op_str,
                        size: insn.bytes.length
                    }));
                    
                    disassembler.close();
                } else {
                    throw new Error("Capstone API mismatch");
                }
            } catch (err) {
                return { error: err.message, instructions: [], count: 0, arch, mode };
            }
            
            return {
                instructions,
                count: instructions.length,
                arch,
                mode
            };
        }

        disassembleSection(uint8Array, sectionInfo) {
            return this.disassemble(
                uint8Array, 
                sectionInfo.arch || this.ARCH.X86, 
                sectionInfo.mode || this.MODE['32'], 
                sectionInfo.address, 
                { offset: sectionInfo.offset, length: sectionInfo.size }
            );
        }

        autoDetectAndDisassemble(uint8Array, binaryParser) {
            const headerInfo = binaryParser.parseHeader(uint8Array);
            if (!headerInfo) throw new Error("Could not detect binary format");
            
            const textSection = headerInfo.sections.find(s => s.name === '.text');
            if (!textSection) throw new Error("No .text section found");
            
            let arch, mode;

            if (headerInfo.format === 'elf') {
                switch(headerInfo.machineId) {
                    case 3: arch = this.ARCH.X86; mode = this.MODE['32']; break; // EM_386
                    case 62: arch = this.ARCH.X86; mode = this.MODE['64']; break; // EM_X86_64
                    case 40: arch = this.ARCH.ARM; mode = this.MODE.ARM; break; // EM_ARM
                    case 183: arch = this.ARCH.ARM64; mode = this.MODE.ARM; break; // EM_AARCH64
                    case 8: arch = this.ARCH.MIPS; mode = this.MODE['32']; break; // EM_MIPS
                    case 20: arch = this.ARCH.PPC; mode = this.MODE['32']; break; // EM_PPC
                    case 21: arch = this.ARCH.PPC; mode = this.MODE['64']; break; // EM_PPC64
                    case 2: arch = this.ARCH.SPARC; mode = this.MODE['32']; break; // EM_SPARC
                    case 43: arch = this.ARCH.SPARC; mode = this.MODE.V9; break; // EM_SPARCV9
                    case 22: arch = this.ARCH.SYSZ; mode = this.MODE.BIG_ENDIAN; break; // EM_S390
                    case 4: arch = this.ARCH.M68K; mode = this.MODE['32']; break; // EM_68K
                    case 243: throw new Error("RISC-V may not be supported by this Capstone version"); // EM_RISCV
                    default: arch = this.ARCH.X86; mode = this.MODE['32'];
                }
            } else if (headerInfo.format === 'pe') {
                switch(headerInfo.machineId) {
                    case 0x14c: arch = this.ARCH.X86; mode = this.MODE['32']; break; // IMAGE_FILE_MACHINE_I386
                    case 0x8664: arch = this.ARCH.X86; mode = this.MODE['64']; break; // IMAGE_FILE_MACHINE_AMD64
                    case 0x1c0: arch = this.ARCH.ARM; mode = this.MODE.ARM; break; // IMAGE_FILE_MACHINE_ARM
                    case 0x1c4: arch = this.ARCH.ARM; mode = this.MODE.THUMB; break; // IMAGE_FILE_MACHINE_ARMNT
                    case 0xaa64: arch = this.ARCH.ARM64; mode = this.MODE.ARM; break; // IMAGE_FILE_MACHINE_ARM64
                    case 0x366: arch = this.ARCH.MIPS; mode = this.MODE['32']; break; // IMAGE_FILE_MACHINE_MIPSFPU
                    case 0x1f0: arch = this.ARCH.PPC; mode = this.MODE['32']; break; // IMAGE_FILE_MACHINE_POWERPC
                    default: arch = this.ARCH.X86; mode = this.MODE['32'];
                }
            } else {
                arch = this.ARCH.X86; mode = this.MODE['32'];
            }
            
            textSection.arch = arch;
            textSection.mode = mode;
            
            return this.disassembleSection(uint8Array, textSection);
        }

        formatInstruction(instr) {
            const bytesPadded = instr.bytesHex.padEnd(24, ' ');
            const mnemonicPadded = instr.mnemonic.padEnd(8, ' ');
            return `${instr.addressHex}: ${bytesPadded} ${mnemonicPadded} ${instr.opStr}`;
        }

        formatForCLI(instructions) {
            return instructions.map(insn => this.formatInstruction(insn)).join('\n');
        }
    }

    return Disassembler;
});

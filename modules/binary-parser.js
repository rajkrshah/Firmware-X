(function(root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.BinaryParser = factory();
    }
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : global), function() {
    'use strict';

    class BinaryParser {
        
        /**
         * Parses ELF Header and Sections
         * @param {Uint8Array} buf 
         */
        parseELF(buf) {
            if (buf.length < 52) throw new Error("Not a valid ELF file (too small)");
            if (buf[0] !== 0x7F || buf[1] !== 0x45 || buf[2] !== 0x4C || buf[3] !== 0x46) throw new Error("Invalid ELF magic");

            const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
            const classType = buf[4]; // 1 = 32-bit, 2 = 64-bit
            const endian = buf[5]; // 1 = LSB, 2 = MSB
            const isLE = endian === 1;

            const header = {
                class: classType === 1 ? 32 : 64,
                endianness: isLE ? 'Little Endian' : 'Big Endian',
                version: buf[6],
                osabi: buf[7],
                type: dv.getUint16(16, isLE),
                machine: dv.getUint16(18, isLE),
                machineStr: this._getMachineStr(dv.getUint16(18, isLE)),
            };

            let e_phoff, e_shoff, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;

            if (header.class === 32) {
                header.entryPoint = dv.getUint32(24, isLE);
                e_phoff = dv.getUint32(28, isLE);
                e_shoff = dv.getUint32(32, isLE);
                header.flags = dv.getUint32(36, isLE);
                e_phentsize = dv.getUint16(42, isLE);
                e_phnum = dv.getUint16(44, isLE);
                e_shentsize = dv.getUint16(46, isLE);
                e_shnum = dv.getUint16(48, isLE);
                e_shstrndx = dv.getUint16(50, isLE);
            } else {
                header.entryPoint = Number(dv.getBigUint64(24, isLE));
                e_phoff = Number(dv.getBigUint64(32, isLE));
                e_shoff = Number(dv.getBigUint64(40, isLE));
                header.flags = dv.getUint32(48, isLE);
                e_phentsize = dv.getUint16(54, isLE);
                e_phnum = dv.getUint16(56, isLE);
                e_shentsize = dv.getUint16(58, isLE);
                e_shnum = dv.getUint16(60, isLE);
                e_shstrndx = dv.getUint16(62, isLE);
            }

            header.phOffset = e_phoff;
            header.shOffset = e_shoff;
            header.phEntSize = e_phentsize;
            header.phNum = e_phnum;
            header.shEntSize = e_shentsize;
            header.shNum = e_shnum;
            header.shStrIndex = e_shstrndx;

            const programHeaders = [];
            for (let i = 0; i < e_phnum; i++) {
                const off = e_phoff + (i * e_phentsize);
                if (off + e_phentsize > buf.length) break;
                
                let p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align;
                if (header.class === 32) {
                    p_type = dv.getUint32(off, isLE);
                    p_offset = dv.getUint32(off + 4, isLE);
                    p_vaddr = dv.getUint32(off + 8, isLE);
                    p_paddr = dv.getUint32(off + 12, isLE);
                    p_filesz = dv.getUint32(off + 16, isLE);
                    p_memsz = dv.getUint32(off + 20, isLE);
                    p_flags = dv.getUint32(off + 24, isLE);
                    p_align = dv.getUint32(off + 28, isLE);
                } else {
                    p_type = dv.getUint32(off, isLE);
                    p_flags = dv.getUint32(off + 4, isLE);
                    p_offset = Number(dv.getBigUint64(off + 8, isLE));
                    p_vaddr = Number(dv.getBigUint64(off + 16, isLE));
                    p_paddr = Number(dv.getBigUint64(off + 24, isLE));
                    p_filesz = Number(dv.getBigUint64(off + 32, isLE));
                    p_memsz = Number(dv.getBigUint64(off + 40, isLE));
                    p_align = Number(dv.getBigUint64(off + 48, isLE));
                }
                programHeaders.push({ type: p_type, offset: p_offset, vaddr: p_vaddr, paddr: p_paddr, filesz: p_filesz, memsz: p_memsz, flags: p_flags, align: p_align });
            }

            const sectionHeaders = [];
            for (let i = 0; i < e_shnum; i++) {
                const off = e_shoff + (i * e_shentsize);
                if (off + e_shentsize > buf.length) break;
                
                let sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize;
                if (header.class === 32) {
                    sh_name = dv.getUint32(off, isLE);
                    sh_type = dv.getUint32(off + 4, isLE);
                    sh_flags = dv.getUint32(off + 8, isLE);
                    sh_addr = dv.getUint32(off + 12, isLE);
                    sh_offset = dv.getUint32(off + 16, isLE);
                    sh_size = dv.getUint32(off + 20, isLE);
                    sh_link = dv.getUint32(off + 24, isLE);
                    sh_info = dv.getUint32(off + 28, isLE);
                    sh_addralign = dv.getUint32(off + 32, isLE);
                    sh_entsize = dv.getUint32(off + 36, isLE);
                } else {
                    sh_name = dv.getUint32(off, isLE);
                    sh_type = dv.getUint32(off + 4, isLE);
                    sh_flags = Number(dv.getBigUint64(off + 8, isLE));
                    sh_addr = Number(dv.getBigUint64(off + 16, isLE));
                    sh_offset = Number(dv.getBigUint64(off + 24, isLE));
                    sh_size = Number(dv.getBigUint64(off + 32, isLE));
                    sh_link = dv.getUint32(off + 40, isLE);
                    sh_info = dv.getUint32(off + 44, isLE);
                    sh_addralign = Number(dv.getBigUint64(off + 48, isLE));
                    sh_entsize = Number(dv.getBigUint64(off + 56, isLE));
                }
                sectionHeaders.push({ nameOffset: sh_name, type: sh_type, flags: sh_flags, addr: sh_addr, offset: sh_offset, size: sh_size, link: sh_link, info: sh_info, addralign: sh_addralign, entsize: sh_entsize });
            }

            // Read section names
            if (e_shstrndx > 0 && e_shstrndx < sectionHeaders.length) {
                const strTabOffset = sectionHeaders[e_shstrndx].offset;
                const strTabSize = sectionHeaders[e_shstrndx].size;
                const strTab = buf.subarray(strTabOffset, strTabOffset + strTabSize);

                for (let sh of sectionHeaders) {
                    let name = '';
                    for (let i = sh.nameOffset; i < strTab.length && strTab[i] !== 0; i++) {
                        name += String.fromCharCode(strTab[i]);
                    }
                    sh.name = name;
                }
            }

            return { header, programHeaders, sectionHeaders };
        }

        /**
         * Parses PE Header
         * @param {Uint8Array} buf 
         */
        parsePE(buf) {
            if (buf.length < 64) throw new Error("File too small to be PE");
            if (buf[0] !== 0x4D || buf[1] !== 0x5A) throw new Error("Invalid DOS magic (MZ)");
            
            const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
            const lfanew = dv.getUint32(60, true);
            if (lfanew >= buf.length || buf[lfanew] !== 0x50 || buf[lfanew+1] !== 0x45) throw new Error("Invalid PE signature");

            const machine = dv.getUint16(lfanew + 4, true);
            const numberOfSections = dv.getUint16(lfanew + 6, true);
            const timeDateStamp = dv.getUint32(lfanew + 8, true);
            const sizeOfOptionalHeader = dv.getUint16(lfanew + 20, true);
            const characteristics = dv.getUint16(lfanew + 22, true);

            const fileHeader = { machine, machineStr: this._getPEMachineStr(machine), numberOfSections, timeDateStamp, characteristics };
            const optionalHeaderOffset = lfanew + 24;
            
            const magic = dv.getUint16(optionalHeaderOffset, true);
            const is64 = magic === 0x20B;

            let entryPoint = dv.getUint32(optionalHeaderOffset + 16, true);
            let imageBase = is64 ? Number(dv.getBigUint64(optionalHeaderOffset + 24, true)) : dv.getUint32(optionalHeaderOffset + 28, true);
            
            const optionalHeader = { magic, entryPoint, imageBase };
            
            const sections = [];
            const sectionOffset = optionalHeaderOffset + sizeOfOptionalHeader;
            for (let i = 0; i < numberOfSections; i++) {
                const off = sectionOffset + (i * 40);
                if (off + 40 > buf.length) break;
                
                let name = '';
                for (let j = 0; j < 8 && buf[off + j] !== 0; j++) {
                    name += String.fromCharCode(buf[off + j]);
                }
                
                sections.push({
                    name,
                    virtualSize: dv.getUint32(off + 8, true),
                    virtualAddress: dv.getUint32(off + 12, true),
                    sizeOfRawData: dv.getUint32(off + 16, true),
                    pointerToRawData: dv.getUint32(off + 20, true),
                    characteristics: dv.getUint32(off + 36, true)
                });
            }

            return { dosHeader: { magic: 'MZ', lfanew }, fileHeader, optionalHeader, sections };
        }

        getArchitectureInfo(buf) {
            try {
                if (buf[0] === 0x7F && buf[1] === 0x45 && buf[2] === 0x4C && buf[3] === 0x46) {
                    const elf = this.parseELF(buf);
                    return { arch: elf.header.machineStr, mode: elf.header.class, endian: elf.header.endianness };
                } else if (buf[0] === 0x4D && buf[1] === 0x5A) {
                    const pe = this.parsePE(buf);
                    return { arch: pe.fileHeader.machineStr, mode: pe.optionalHeader.magic === 0x20B ? 64 : 32, endian: 'Little Endian' };
                }
            } catch (e) {
                return null;
            }
            return null;
        }

        _getMachineStr(machine) {
            const map = {
                0: 'No machine',
                2: 'SPARC',
                3: 'Intel 80386 (x86)',
                4: 'Motorola 68000',
                5: 'Motorola 88000',
                8: 'MIPS',
                20: 'PowerPC',
                21: 'PowerPC 64-bit',
                22: 'IBM System/390',
                40: 'ARM',
                42: 'SuperH',
                43: 'SPARC V9',
                50: 'Intel Itanium',
                62: 'AMD x86-64',
                83: 'Atmel AVR (Arduino)',
                84: 'Fujitsu FR30',
                87: 'NEC V850',
                88: 'Mitsubishi M32R',
                89: 'Matsushita MN10300',
                94: 'Tensilica Xtensa (ESP32/ESP8266)',
                105: 'TI MSP430',
                106: 'Analog Devices Blackfin DSP',
                113: 'Altera Nios II',
                140: 'TI TMS320C6000 DSP',
                165: 'Intel 8051',
                183: 'ARM 64-bit (AArch64)',
                188: 'Tilera TILEPro',
                189: 'Xilinx MicroBlaze',
                191: 'Tilera TILE-Gx',
                195: 'Synopsys ARCv2',
                243: 'RISC-V',
                247: 'Linux BPF',
                252: 'C-SKY'
            };
            return map[machine] || `Unknown (${machine})`;
        }
        
        _getPEMachineStr(machine) {
            const map = {
                0x0: 'Unknown',
                0x14c: 'x86 (i386)',
                0x166: 'MIPS little-endian (R3000)',
                0x168: 'MIPS little-endian (R4000)',
                0x169: 'MIPS little-endian WCE v2',
                0x1a2: 'Hitachi SH3',
                0x1a3: 'Hitachi SH3 DSP',
                0x1a6: 'Hitachi SH4',
                0x1a8: 'Hitachi SH5',
                0x1c0: 'ARM little-endian',
                0x1c4: 'ARM Thumb-2',
                0x1d3: 'Matsushita AM33',
                0x1f0: 'PowerPC little-endian',
                0x1f1: 'PowerPC with FPU',
                0x200: 'Intel Itanium (IA-64)',
                0x266: 'MIPS16',
                0x366: 'MIPS with FPU',
                0x466: 'MIPS16 with FPU',
                0xebc: 'EFI Byte Code',
                0x5032: 'RISC-V 32-bit',
                0x5064: 'RISC-V 64-bit',
                0x5128: 'RISC-V 128-bit',
                0x8664: 'x86-64 (AMD64)',
                0x9041: 'Mitsubishi M32R',
                0xaa64: 'ARM64 (AArch64)',
                0xc0ee: 'Microsoft CLR'
            };
            return map[machine] || `Unknown (${machine})`;
        }
    }

    return BinaryParser;
});

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include <conio.h> // TODO(mdizdar): this is just for getch, remove this and all the other terminal based bullshit when you make a proper GUI

#include "printing.h"
#include "types.h"

#define RAMEND 0x045F

constexpr u64 Kilobytes(u64 x) { return x * 1024; }
constexpr u64 Megabytes(u64 x) { return Kilobytes(x) * 1024; }

u8 flash[Kilobytes(16)];
u8 EEPROM[512];
//u8 SRAM[Kilobytes(1)];

union {
    struct {
        u8 registers[32];
        union {
            struct {
                u8 IO_registers[32];
                u8 IO_registers_NBA[32];
                u8 extended_IO_registers[160];
            };
            u8 IO_space[32+32+160];
        };
        u8 internal_SRAM[RAMEND-(32+32+32+160)+1];
    };
    u8 memory[RAMEND+1];
} memory;

u8 * const registers = memory.registers;
u8 * const IO_registers = memory.IO_registers;
u8 * const IO_space = memory.IO_space;
u8 * const SRAM = memory.memory;
union Status {
    struct {
        u8 C:1;
        u8 Z:1;
        u8 N:1;
        u8 V:1;
        u8 S:1;
        u8 H:1;
        u8 T:1;
        u8 I:1;
    };
    struct {
        u8 _0:1;
        u8 _1:1;
        u8 _2:1;
        u8 _3:1;
        u8 _4:1;
        u8 _5:1;
        u8 _6:1;
        u8 _7:1;
    };
    u8 value;
} * const sreg = (union Status *)&IO_space[0x3F];
u16 * const sp = (u16 *)&IO_space[0x3D];
u8 * const eind = &IO_space[0x3C];
u8 * const rampz = &IO_space[0x3B];
u8 * const rampy = &IO_space[0x3A];
u8 * const rampx = &IO_space[0x39];
u8 * const rampd = &IO_space[0x38];
u16 *X = (u16 *)&registers[26];
u16 *Y = (u16 *)&registers[28];
u16 *Z = (u16 *)&registers[30];

u8 *PORTA = &IO_space[0x1B];
u8 *PORTB = &IO_space[0x18];
u8 *PORTC = &IO_space[0x15];
u8 *PORTD = &IO_space[0x12];

u8 *DDRA = &IO_space[0x1A];
u8 *DDRB = &IO_space[0x17];
u8 *DDRC = &IO_space[0x14];
u8 *DDRD = &IO_space[0x11];

u8 *PINA = &IO_space[0x19];
u8 *PINB = &IO_space[0x16];
u8 *PINC = &IO_space[0x13];
u8 *PIND = &IO_space[0x10];

typedef struct {
    char *data;
    u64 count;
} String;

String read_file(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    String file_data;
    fseek(fp, 0L, SEEK_END);
    file_data.count = ftell(fp);
    rewind(fp);
    file_data.data = (char *)malloc((file_data.count+1) * sizeof(char));
    fread(file_data.data, sizeof(char), file_data.count, fp);
    fclose(fp);
    file_data.data[file_data.count] = 0;
    return file_data;
}

u64 hex(char c) {
    if (c >= '0' && c <= '9') return c-'0';
    if (c >= 'A' && c <= 'F') return c-'A'+10;
    if (c >= 'a' && c <= 'f') return c-'a'+10;
    error(-1, "unrecognized character in hex string");
}

void load_into_flash(const char *filename) {
    String file_data = read_file(filename);
    // parse intel hex
    enum {
        IntelHexColon,
        IntelHexCount,
        IntelHexAddress,
        IntelHexType,
        IntelHexData,
        IntelHexChecksum
    } state = IntelHexColon;
    
    const u64 base_address = 0; // NOTE(mdizdar): make sure this is correct
    
    u64 count = 0;
    u64 address = 0;
    u64 type = 0;
    u64 lineno = 1;
    u8 checksum = 0;
    for (u64 i = 0; i < file_data.count; ++i) {
        if (file_data.data[i] == '\n') ++lineno;
        switch (state) {
            case IntelHexColon: {
                if (file_data.data[i] == ':') {
                    state = IntelHexCount;
                    count = 0;
                }
            } break;
            case IntelHexCount: {
                // NOTE(mdizdar): probably should make an assert that i+1 won't be out of bounds
                count = 16*hex(file_data.data[i])+hex(file_data.data[i+1]);
                ++i;
                state = IntelHexAddress;
                address = 0;
            } break;
            case IntelHexAddress: {
                address = 
                    16*16*16*hex(file_data.data[i])+
                    16*16*hex(file_data.data[i+1])+
                    16*hex(file_data.data[i+2])+
                    hex(file_data.data[i+3]);
                i += 3;
                state = IntelHexType;
                type = 0;
            } break;
            case IntelHexType: {
                type = 16*hex(file_data.data[i])+hex(file_data.data[i+1]);
                ++i;
                state = IntelHexData;
                checksum = count + (address&0xFF) + (address>>8) + type;
            } break;
            case IntelHexData: {
                for (u64 j = 0; j < count; ++j) {
                    flash[base_address+address+j] = 16*hex(file_data.data[i]) + hex(file_data.data[i+1]);
                    i += 2;
                    checksum += flash[base_address+address+j];
                }
                --i;
                state = IntelHexChecksum;
                checksum = -checksum;
            } break;
            case IntelHexChecksum: {
                u8 correct_checksum = 16*hex(file_data.data[i]) + hex(file_data.data[i+1]);
                ++i;
                if (correct_checksum != checksum) {
                    error(lineno, "incorrect checksum when parsing %s. Got 0x%02X, expected 0x%02X", filename, checksum, correct_checksum);
                }
                state = IntelHexColon;
            } break;
            default: {
                internal_error(__FILE__, __LINE__); 
            }
        }
    }
}

void print_AVR_instruction(u16 instruction, u16 address=0) {
    if ((instruction & 0xFC0F) == 0x9000) {
        // LDS/STS - 32-bit instruction
        const u16 SRAMaddress = address;
        const u16 reg = instruction & 0x003F;
        if (instruction & 0x0200) {
            // STS
            printf("[0x%04x%04x]\tsts r%d, 0x%x\n", instruction, SRAMaddress, reg, SRAMaddress << 1);
        } else {
            // LDS
            printf("[0x%04x%04x]\tlds 0x%x, r%d\n", instruction, SRAMaddress, SRAMaddress << 1, reg);
        }
        return;
    }
    if ((instruction & 0xFE0C) == 0x940C) {
        // JMP/CALL - 32-bit instruction
        const u16 hi = address;
        const u32 SRAMaddress = hi | ((instruction & 0x01F0) << 14) | ((instruction & 0x0001) << 16);
        if (instruction & 0x0002) {
            // CALL
            printf("[0x%04x%04x]\tcall 0x%x\n", instruction, hi, SRAMaddress << 1);
        } else {
            // JMP
            printf("[0x%04x%04x]\tjmp 0x%x\n", instruction, hi, SRAMaddress << 1);
        }
        return;
    }
    
    // from here on it's only 16 bit instructions
    
    if (instruction == 0) {
        // NOP
        printf("[0x0000]\tnop\n");
    } else if ((instruction >> 8) == 1) {
        // MOVW
        const u16 r1 = instruction & 0xF;
        const u16 r2 = (instruction & 0xF0) >> 4;
        printf("[0x%04x]\tmovw r%d, r%d\n", instruction, r2*2, r1*2);
    } else if ((instruction >> 8) == 2) {
        // MULS
        const u16 r1 = instruction & 0xF;
        const u16 r2 = (instruction & 0xF0) >> 4;
        printf("[0x%04x]\tmuls r%d, r%d\n", instruction, r2+16, r1+16);
    } else if ((instruction & 0xFF88) == 0x0300) {
        // MULSU
        const u16 r1 = instruction & 0x7;
        const u16 r2 = (instruction & 0x70) >> 4;
        printf("[0x%04x]\tmulsu r%d, r%d\n", instruction, r2+16, r1+16);
    } else if ((instruction & 0xFF88) == 0x0308) {
        // FMUL
        const u16 r1 = instruction & 0x7;
        const u16 r2 = (instruction & 0x70) >> 4;
        printf("[0x%04x]\tfmul r%d, r%d\n", instruction, r2+16, r1+16);
    } else if ((instruction & 0xFF88) == 0x0380) {
        // FMULS
        const u16 r1 = instruction & 0x7;
        const u16 r2 = (instruction & 0x70) >> 4;
        printf("[0x%04x]\tfmuls r%d, r%d\n", instruction, r2+16, r1+16);
    } else if ((instruction & 0xFF88) == 0x0388) {
        // FMULSU
        const u16 r1 = instruction & 0x7;
        const u16 r2 = (instruction & 0x70) >> 4;
        printf("[0x%04x]\tfmulsu r%d, r%d\n", instruction, r2+16, r1+16);
    } else if ((instruction & 0xF000) == 0x3000) {
        // CPI
        const u16 value = ((instruction >> 4) & 0xF0) + (instruction & 0xF);
        const u16 reg = (instruction >> 4) & 0xF;
        printf("[0x%04x]\tcpi r%d, 0x%x\n", instruction, reg+16, value);
    } else if ((instruction >> 14) == 0) {
        // 2-op instruction
        const u16 r2 = (instruction & 0xF) | ((instruction & 0x200) >> 5);
        const u16 r1 = (instruction & 0x1F0) >> 4;
        const u8 op = (instruction & 0x3C00) >> 10;
        const char * opnames[12];
        opnames[0] = ""; opnames[1] = "cpc"; opnames[2] = "sbc"; opnames[3] = "add";
        opnames[4] = "cpse"; opnames[5] = "cp"; opnames[6] = "sub"; opnames[7] = "adc";
        opnames[8] = "and"; opnames[9] = "eor"; opnames[10] = "or"; opnames[11] = "mov";
        printf("[0x%04x]\t%s r%d, r%d\n", instruction, opnames[op], r1, r2);
    } else if ((instruction >> 14) == 0x1) {
        // register-immediate instructions
        const u16 value = ((instruction >> 4) & 0xF0) + (instruction & 0xF);
        const u16 reg = (instruction >> 4) & 0xF;
        const u16 op = (instruction & 0x3000) >> 12;
        const char * opnames[4];
        opnames[0] = "sbci"; opnames[1] = "subi"; opnames[2] = "ori"; opnames[3] = "andi";
        printf("[0x%04x]\t%s r%d, 0x%x\n", instruction, opnames[op], reg+16, value);
    } else if ((instruction >> 10) == 0x24) {
        // load/store instructions
        const u16 reg = (instruction & 0x01F0) >> 4;
        const u8 op = (u8)((instruction & 0xF) | ((instruction & 0x200) >> 5));
        const char * opcodes[32];
        const char * after[32];
        opcodes[0] = "lds"; opcodes[1] = "ld"; opcodes[2] = "ld"; opcodes[3] = "";
        opcodes[4] = "lpm"; opcodes[5] = "lpm"; opcodes[6] = "elpm"; opcodes[7] = "elpm";
        opcodes[8] = ""; opcodes[9] = "ld"; opcodes[10] = "ld"; opcodes[11] = "";
        opcodes[12] = "ld"; opcodes[13] = "ld"; opcodes[14] = "ld"; opcodes[15] = "pop";
        opcodes[16] = "sts"; opcodes[17] = "st"; opcodes[18] = "st"; opcodes[19] = "";
        opcodes[20] = "xch z,"; opcodes[21] = "las z,"; opcodes[22] = "lac z,";
        opcodes[23] = "lat z,"; opcodes[24] = ""; opcodes[25] = "st"; opcodes[26] = "st";
        opcodes[27] = ""; opcodes[28] = "st"; opcodes[29] = "st"; opcodes[30] = "st";
        opcodes[31] = "push";
        after[0] = ""; after[1] = ", y+"; after[2] = ", -y"; after[3] = "";
        after[4] = ", z"; after[5] = ", z+"; after[6] = ", z"; after[7] = ", z+";
        after[8] = ""; after[9] = ", z+"; after[10] = ", -z"; after[11] = "";
        after[12] = ", x"; after[13] = ", x+"; after[14] = ", -x"; after[15] = "";
        after[16] = ""; after[17] = ", y+"; after[18] = ", -y"; after[19] = "";
        after[20] = ""; after[21] = ""; after[22] = ""; after[23] = ""; after[24] = "";
        after[25] = ", z+"; after[26] = ", -z"; after[27] = ""; after[28] = ", x";
        after[29] = ", x+"; after[30] = ", -x"; after[31] = "";
        printf("[0x%04x]\t%s r%d%s\n", instruction, opcodes[op], reg, after[op]);
    } else if ((instruction & 0xD000) == 0x8000) {
        // LDD/STD
        const u16 reg = (instruction & 0x01F0) >> 4;
        const u16 value = (instruction & 0x7) | ((instruction >> 7) & 0x0018) | ((instruction >> 7) & 0x0020);
        const u8 y = (instruction & 0x8) >> 3;
        const u8 s = (instruction & 0x0200) >> 9;
        const char * opnames[2];
        opnames[0] = "ldd";
        opnames[1] = "std";
        const char * after[2];
        after[0] = ", z";
        after[1] = ", y";
        printf("[0x%04x]\t%s r%d%s+%d\n", instruction, opnames[s], reg, after[y], value);
    } else if ((instruction & 0xFE08) == 0x9400) {
        // 1-op instructions
        const u16 reg = (instruction & 0x01F0) >> 4;
        const u8 op = instruction & 0x7;
        const char * opnames[8];
        opnames[0] = "com"; opnames[1] = "neg"; opnames[2] = "swap"; opnames[3] = "inc";
        opnames[4] = ""; opnames[5] = "asr"; opnames[6] = "lsr"; opnames[7] = "ror";
        if (op == 4) {
            error(0, "opcode 0x9408 doesn't exist ");
        }
        printf("[0x%04x]\t%s r%d\n", instruction, opnames[op], reg);
    } else if ((instruction & 0xFF0F) == 0x9408) {
        // SEx/CLx
        const u16 bit = (instruction & 0x0070) >> 4;
        const u8 op = (instruction & 0x0080) >> 7;
        const char * bitnames = "cznvshti";
        const char * opnames[] = {"se", "cl"};
        printf("[0x%04x]\t%s%c\n", instruction, opnames[op], bitnames[bit]);
    } else if ((instruction & 0xFF0F) == 0x9508) {
        // 0-op instructions
        const u8 op = (instruction & 0xF0) >> 4;
        const char * opnames[16];
        opnames[0] = "ret"; opnames[1] = "reti"; opnames[2] = ""; opnames[3] = "";
        opnames[4] = ""; opnames[5] = ""; opnames[6] = ""; opnames[7] = "";
        opnames[8] = "sleep"; opnames[9] = "break"; opnames[10] = "wdr"; opnames[11] = "";
        opnames[12] = "lpm"; opnames[13] = "elpm"; opnames[14] = "spm"; opnames[15] = "spm z+";
        if (!strcmp(opnames[op], "")) {
            error(0, "0-op opcode doesn't exist");
        }
        printf("[0x%04x]\t%s\n", instruction, opnames[op]);
    } else if ((instruction & 0xFEEF) == 0x9409) {
        // Indirect jump/call to Z or EIND:Z
        const u8 op = (u8)(((instruction & 0x0100) >> 7) | (instruction & 0x0010) >> 4);
        const char * opnames[4];
        opnames[0] = "ijmp";
        opnames[1] = "eijmp";
        opnames[2] = "icall";
        opnames[3] = "eicall";
        printf("[0x%04x]\t%s\n", instruction, opnames[op]);
    } else if ((instruction & 0xFE0F) == 0x940A) {
        // DEC
        const u16 reg = (instruction & 0x01F0) >> 4;
        printf("[0x%04x]\tdec r%d\n", instruction, reg);
    } else if ((instruction & 0xFF0F) == 0x940B) {
        // DES
        const u16 value = (instruction & 0x00F0) >> 4;
        printf("[0x%04x]\tdes 0x%x\n", instruction, value);
    } else if ((instruction & 0xFE00) == 0x9600) {
        // ADIW/SBIW
        const u8 value = (instruction & 0x000F) | ((instruction & 0x00C0) >> 2);
        const u8 reg = (instruction & 0x0030) >> 4;
        const u8 op = (instruction & 0x0100) >> 8;
        const char * opnames[2];
        opnames[0] = "adiw";
        opnames[1] = "sbiw";
        printf("[0x%04x]\t%s r%d, 0x%x\t", instruction, opnames[op], (reg+12)*2, value);
    } else if ((instruction & 0xFC00) == 0x9800) {
        // CBI/SBI/SBIC/SBIS
        const u8 value = (instruction & 0x00F8) >> 3;
        const u8 bit = instruction & 0x7;
        const u8 op = (instruction & 0x0300) >> 8;
        const char * opnames[4];
        opnames[0] = "cbi";
        opnames[1] = "sbic";
        opnames[2] = "sbi";
        opnames[3] = "sbis";
        printf("[0x%04x]\t%s 0x%x, 0x%x\n", instruction, opnames[op], value, bit);
    } else if ((instruction & 0xFC00) == 0x9C00) {
        // MUL, unsigned: R1:R0 = Rr x Rd
        const u16 r1 = (instruction & 0xF) | ((instruction & 0x200) >> 5);
        const u16 r2 = (instruction & 0x1F0) >> 4;
        printf("[0x%04x]\tmul r%d, r%d\n", instruction, r2, r1);
    } else if ((instruction & 0xF000) == 0xB000) {
        // IN/OUT to I/O space
        const u16 address = (instruction & 0xF) | ((instruction & 0x600) >> 5);
        const u16 reg = (instruction & 0x1F0) >> 4;
        if (instruction & 0x0800) {
            printf("[0x%04x]\tout 0x%x, r%d\n", instruction, address, reg);
        } else {
            printf("[0x%04x]\tin r%d, 0x%x\n", instruction, reg, address);
        }
    } else if ((instruction & 0xE000) == 0xC000) {
        // RJMP/RCALL
        s16 offset = instruction & 0x0FFF;
        if (offset & 0x0800) {
            offset -= 1 << 12;
        }
        if (instruction & 0x1000) {
            printf("[0x%04x]\trcall %d\n", instruction, offset*2);
        } else {
            printf("[0x%04x]\trjmp %d\n", instruction, offset*2); // NOTE(mdizdar): the offset may be incorrect, figure it out
        }
    } else if ((instruction >> 12) == 0xE) {
        // LDI
        const u16 value = ((instruction >> 4) & 0xF0) + (instruction & 0xF);
        const u16 reg = (instruction >> 4) & 0xF;
        printf("[0x%04x]\tldi r%d, 0x%x\n", instruction, reg+16, value);
    } else if ((instruction & 0xF800) == 0xF000) {
        // breaks
        s8 offset = (s8)((instruction & 0x03F8) >> 3);
        if (offset & 0x40) {
            offset -= 1 << 7;
        }
        const u8 op = (u8)((instruction & 0x7) | ((instruction & 0x0400) >> 7));
        const char * opnames[16];
        opnames[0] = "brcs"; opnames[1] = "breq"; opnames[2] = "brmi"; opnames[3] = "brvs";
        opnames[4] = "brlt"; opnames[5] = "brhs"; opnames[6] = "brts"; opnames[7] = "brie";
        opnames[8] = "brcc"; opnames[9] = "brne"; opnames[10] = "brpl";
        opnames[11] = "brvc"; opnames[12] = "brge"; opnames[13] = "brhc"; 
        opnames[14] = "brtc"; opnames[15] = "brid";
        printf("[0x%04x]\t%s %d\n", instruction, opnames[op], offset*2);
    } else if ((instruction & 0xFC08) == 0xF800) {
        //BLD/BST
        const u8 bit = (instruction & 0x7);
        const u16 reg = (instruction >> 4) & 0xF;
        if (instruction & 0x0200) {
            printf("[0x%04x]\tbst r%d, %u\n", instruction, reg, bit);
        } else {
            printf("[0x%04x]\tbld r%d, %u\n", instruction, reg, bit);
        }
    } else if ((instruction & 0xFC08) == 0xFC00) {
        // SBRC/SBRS
        const u8 bit = (instruction & 0x7);
        const u16 reg = (instruction >> 4) & 0xF;
        if (instruction & 0x0200) {
            printf("[0x%04x]\tsbrs r%d, %u\n", instruction, reg, bit);
        } else {
            printf("[0x%04x]\tsbrc r%d, %u\n", instruction, reg, bit);
        }
    } else {
        error(0, "You have invented a new AVR instruction, gz");
    }
}

void display_state() {
    //system("cls");
    printf("\033[%d;%dH", 1, 1);
    puts("===============================================================");
    Status *reg = (Status *)PORTA;
    printf("PORTA: [%c%c%c%c%c%c%c%c] %3hhu |\t", 
           reg->_7?'.':'#', reg->_6?'.':'#', reg->_5?'.':'#', reg->_4?'.':'#', 
           reg->_3?'.':'#', reg->_2?'.':'#', reg->_1?'.':'#', reg->_0?'.':'#',
           ~reg->value);
    reg = (Status *)PORTB;
    printf("PORTB: [%c%c%c%c%c%c%c%c] %3hhu\n", 
           reg->_7?'.':'#', reg->_6?'.':'#', reg->_5?'.':'#', reg->_4?'.':'#', 
           reg->_3?'.':'#', reg->_2?'.':'#', reg->_1?'.':'#', reg->_0?'.':'#',
           reg->value);
    reg = (Status *)PORTC;
    printf("PORTC: [%c%c%c%c%c%c%c%c] %3hhu |\t", 
           reg->_7?'.':'#', reg->_6?'.':'#', reg->_5?'.':'#', reg->_4?'.':'#', 
           reg->_3?'.':'#', reg->_2?'.':'#', reg->_1?'.':'#', reg->_0?'.':'#',
           reg->value);
    reg = (Status *)PORTD;
    printf("PORTD: [%c%c%c%c%c%c%c%c] %3hhu\n", 
           reg->_7?'.':'#', reg->_6?'.':'#', reg->_5?'.':'#', reg->_4?'.':'#', 
           reg->_3?'.':'#', reg->_2?'.':'#', reg->_1?'.':'#', reg->_0?'.':'#',
           reg->value);
    reg = sreg;
    printf("SREG:  [%c%c%c%c%c%c%c%c]\n", 
           reg->_7?'#':'.', reg->_6?'#':'.', reg->_5?'#':'.', reg->_4?'#':'.', 
           reg->_3?'#':'.', reg->_2?'#':'.', reg->_1?'#':'.', reg->_0?'#':'.');
    puts("===============================================================");
#ifdef SHOW_MEMORY
    static u64 draw_address_begin = 0;
    char c = 0;
    if (kbhit()) c = getch();
    if (c == 's' || c == 'S') {
        draw_address_begin += 16;
    } else if (c == 'w' || c == 'W') {
        if (draw_address_begin) {
            draw_address_begin -= 16;
        }
    }
    for (u64 i = 0; i < 256; ++i) {
        if (i % 16 == 0) printf("\n[0x%04X] ", draw_address_begin+i);
        printf("%02hhX ", SRAM[draw_address_begin+i]);
    }
#endif
    usleep(1000000/15);
}

int main(int argc, char **argv) {
    load_into_flash(argv[1]);
    
    const u16 *flash16 = (u16 *)flash;
    
    for (u64 i = 0; i < 120; ++i) {
        printf("0x%04X ", flash16[i]);
        if (i % 10 == 9) printf("\n");
    }
    system("cls");
    u64 total_clocks = 0;
    u8 pa = *PORTA;
    for (u16 pc = 0; pc < Kilobytes(16); ++pc) {
#ifdef DEBUG
        display_state();
        printf("PC: 0x%04X\n", pc*2);
        printf("total clocks: %llu\nREGS: ", total_clocks);
        for (u16 reg = 0; reg < 32; ++reg) {
            printf("0x%02X ", registers[reg]);
        }
        printf("\nSTACK: ");
        for (u16 s = RAMEND-1, i = 0; s >= *sp && i < 20; --s, ++i) {
            printf("0x%02X ", SRAM[s]);
        }
        getchar();
#else
        if (total_clocks > 8000000/15) {
            display_state();
            total_clocks = 0;
        }
        
        /*if (*PORTA != pa) {
            printf("PORTA: 0x%02X %hhu %llu\n", *PORTA, ~*PORTA, total_clocks);
            pa = *PORTA;
        }*/
#endif
        
        u8 clocks = 0;
        const u16 instruction = flash16[pc];
        //print_AVR_instruction(instruction);
        u16 print_address = 0;
        // TODO(mdizdar): make sure all of these can actually get executed cause who knows
        if (instruction == 0) {
            // NOP
            //puts("NOP");
            clocks = 1;
        } else if ((instruction & 0xFF00) == 0x0100) {
            // MOVW
            //puts("MOVW");
            const u16 r1 = instruction & 0xF;
            const u16 r2 = (instruction & 0xF0) >> 4;
            u16 *R1 = (u16 *)&registers[r1*2];
            u16 *R2 = (u16 *)&registers[r2*2];
            *R2 = *R1;
            clocks = 1;
        } else if ((instruction & 0xFF00) == 0x0200) {
            // MULS
            const u16 r1 = instruction & 0xF;
            const u16 r2 = (instruction & 0xF0) >> 4;
            s8 *R1 = (s8 *)&registers[r1+16];
            s8 *R2 = (s8 *)&registers[r2+16];
            s16 *res = (s16 *)&registers[0];
            *res = (s16)*R1 * (s16)*R2;
            sreg->Z = !*res;
            sreg->C = (*res) >> 15;
            clocks = 2;
        } else if ((instruction & 0xFF88) == 0x0300) {
            // MULSU
            const u16 r1 = instruction & 0x7;
            const u16 r2 = (instruction & 0x70) >> 4;
            u8 *R1 = &registers[r1+16];
            s8 *R2 = (s8 *)&registers[r2+16];
            s16 *res = (s16 *)&registers[0];
            *res = (u16)*R1 * (s16)*R2;
            sreg->Z = !*res;
            sreg->C = (*res) >> 15;
            clocks = 2;
        } else if ((instruction & 0xFF88) == 0x0308) {
            // FMUL
            const u16 r1 = instruction & 0x7;
            const u16 r2 = (instruction & 0x70) >> 4;
            u8 *R1 = &registers[r1+16];
            u8 *R2 = (u8 *)&registers[r2+16];
            u16 *res = (u16 *)&registers[0];
            *res = ((u16)*R1 * (u16)*R2);
            sreg->C = (*res) >> 15;
            *res <<= 1;
            sreg->Z = !*res;
            clocks = 2;
        } else if ((instruction & 0xFF88) == 0x0380) {
            // FMULS
            const s16 r1 = instruction & 0x7;
            const s16 r2 = (instruction & 0x70) >> 4;
            s8 *R1 = (s8 *)&registers[r1+16];
            s8 *R2 = (s8 *)&registers[r2+16];
            s16 *res = (s16 *)&registers[0];
            *res = ((s16)*R1 * (u16)*R2);
            sreg->C = (*res) >> 15;
            *res <<= 1;
            sreg->Z = !*res;
            clocks = 2;
        } else if ((instruction & 0xFF88) == 0x0388) {
            // FMULSU
            const u16 r1 = instruction & 0x7;
            const s16 r2 = (instruction & 0x70) >> 4;
            u8 *R1 = &registers[r1+16];
            s8 *R2 = (s8 *)&registers[r2+16];
            s16 *res = (s16 *)&registers[0];
            *res = ((u16)*R1 * (s16)*R2);
            sreg->C = (*res) >> 15;
            *res <<= 1;
            sreg->Z = !*res;
            clocks = 2;
        } else if ((instruction & 0xFC00) == 0x0400) {
            // CPC
            //puts("CPC");
            const u16 r2 = (instruction & 0xF) | ((instruction & 0x200) >> 5);
            const u16 r1 = (instruction & 0x1F0) >> 4;
            const Status R2 = {.value = registers[r2]};
            const Status R1 = {.value = registers[r1]};
            const Status res = {.value = R1.value - R2.value - sreg->C};
            sreg->H = !R1._3&R2._3 | R2._3&res._3 | res._3&!R1._3;
            sreg->N = res._7;
            sreg->V = R1._7&!R2._7&!res._7 | !R1._7&R2._7&res._7;
            sreg->S = sreg->N ^ sreg->V;
            sreg->Z = sreg->Z = res.value ? 0 : sreg->Z;
            sreg->C = !R1._7&R2._7 | R2._7&res._7 | res._7*!R1._7;
            clocks = 1;
        } else if ((instruction & 0xFC00) == 0x1400) {
            // CP
            //puts("CP");
            const u16 r2 = (instruction & 0xF) | ((instruction & 0x200) >> 5);
            const u16 r1 = (instruction & 0x1F0) >> 4;
            const Status R2 = {.value = registers[r2]};
            const Status R1 = {.value = registers[r1]};
            const Status res = {.value = R1.value - R2.value};
            sreg->H = !R1._3&R2._3 | R2._3&res._3 | res._3&!R1._3;
            sreg->N = res._7;
            sreg->V = R1._7&!R2._7&!res._7 | !R1._7&R2._7&res._7;
            sreg->S = sreg->N ^ sreg->V;
            sreg->Z = sreg->Z = res.value ? 0 : sreg->Z;
            sreg->C = !R1._7&R2._7 | R2._7&res._7 | res._7*!R1._7;
            clocks = 1;
        } else if ((instruction & 0xFC00) == 0x0800) {
            // SBC
            //puts("SBC");
            const u16 r2 = (instruction & 0xF) | ((instruction & 0x200) >> 5);
            const u16 r1 = (instruction & 0x1F0) >> 4;
            const Status R2 = {.value = registers[r2]};
            const Status R1 = {.value = registers[r1]};
            const Status res = {.value = R1.value - R2.value - sreg->C};
            sreg->H = !R1._3&R2._3 | R2._3&res._3 | res._3&!R1._3;
            sreg->N = res._7;
            sreg->V = R1._7&!R2._7&!res._7 | !R1._7&R2._7&res._7;
            sreg->S = sreg->N ^ sreg->V;
            sreg->Z = res.value ? 0 : sreg->Z;
            sreg->C = !R1._7&R2._7 | R2._7&res._7 | res._7*!R1._7;
            registers[r1] = res.value;
            clocks = 1;
        } else if ((instruction & 0xFC00) == 0x1800) {
            // SUB
            //puts("SUB");
            const u16 r2 = (instruction & 0xF) | ((instruction & 0x200) >> 5);
            const u16 r1 = (instruction & 0x1F0) >> 4;
            const Status R2 = {.value = registers[r2]};
            const Status R1 = {.value = registers[r1]};
            const Status res = {.value = R1.value - R2.value};
            sreg->H = !R1._3&R2._3 | R2._3&res._3 | res._3&!R1._3;
            sreg->N = res._7;
            sreg->V = R1._7&!R2._7&!res._7 | !R1._7&R2._7&res._7;
            sreg->S = sreg->N ^ sreg->V;
            sreg->Z = res.value ? 0 : sreg->Z;
            sreg->C = !R1._7&R2._7 | R2._7&res._7 | res._7*!R1._7;
            registers[r1] = res.value;
            clocks = 1;
        } else if ((instruction & 0xFC00) == 0x0C00) {
            // ADD
            //puts("ADD");
            const u16 r2 = (instruction & 0xF) | ((instruction & 0x200) >> 5);
            const u16 r1 = (instruction & 0x1F0) >> 4;
            const Status R2 = {.value = registers[r2]};
            const Status R1 = {.value = registers[r1]};
            const Status res = {.value = R1.value + R2.value};
            sreg->H = R1._3&R2._3 | R2._3&!res._3 | !res._3&R1._3;
            sreg->N = res._7;
            sreg->V = R1._7&R2._7&!res._7 | !R1._7&!R2._7&res._7;
            sreg->S = sreg->N ^ sreg->V;
            sreg->Z = res.value == 0;
            sreg->C = R1._7&R2._7 | R2._7&!res._7 | !res._7*R1._7;
            registers[r1] = res.value;
            clocks = 1;
        } else if ((instruction & 0xFC00) == 0x1C00) {
            // ADC
            //puts("ADC");
            const u16 r2 = (instruction & 0xF) | ((instruction & 0x200) >> 5);
            const u16 r1 = (instruction & 0x1F0) >> 4;
            const Status R2 = {.value = registers[r2]};
            const Status R1 = {.value = registers[r1]};
            const Status res = {.value = R1.value + R2.value + sreg->C};
            sreg->H = R1._3&R2._3 | R2._3&!res._3 | !res._3&R1._3;
            sreg->N = res._7;
            sreg->V = R1._7&R2._7&!res._7 | !R1._7&!R2._7&res._7;
            sreg->S = sreg->N ^ sreg->V;
            sreg->Z = res.value == 0;
            sreg->C = R1._7&R2._7 | R2._7&!res._7 | !res._7*R1._7;
            registers[r1] = res.value;
            clocks = 1;
        } else if ((instruction & 0xFC00) == 0x1000) {
            // CPSE
            //puts("CPSE");
            const u16 r2 = (instruction & 0xF) | ((instruction & 0x200) >> 5);
            const u16 r1 = (instruction & 0x1F0) >> 4;
            if (registers[r1] == registers[r2]) {
                u16 next_instruction = flash16[pc+1];
                if ((instruction & 0xFC0F) == 0x9000 || (instruction & 0xFE0C) == 0x940C) {
                    clocks = 3;
                    pc += 2;
                } else {
                    clocks = 2;
                    ++pc;
                }
            } else {
                clocks = 1;
            }
        } else if ((instruction & 0xFC00) == 0x2000) {
            // AND
            //puts("AND");
            const u16 r2 = (instruction & 0xF) | ((instruction & 0x200) >> 5);
            const u16 r1 = (instruction & 0x1F0) >> 4;
            const Status R2 = {.value = registers[r2]};
            const Status R1 = {.value = registers[r1]};
            const Status res = {.value = R1.value & R2.value};
            sreg->N = res._7;
            sreg->V = 0;
            sreg->S = sreg->N ^ sreg->V;
            sreg->Z = res.value == 0;
            registers[r1] = res.value;
            clocks = 1;
        } else if ((instruction & 0xFC00) == 0x2400) {
            // EOR
            //puts("EOR");
            const u16 r2 = (instruction & 0xF) | ((instruction & 0x200) >> 5);
            const u16 r1 = (instruction & 0x1F0) >> 4;
            const Status R2 = {.value = registers[r2]};
            const Status R1 = {.value = registers[r1]};
            const Status res = {.value = R1.value ^ R2.value};
            sreg->N = res._7;
            sreg->V = 0;
            sreg->S = sreg->N ^ sreg->V;
            sreg->Z = res.value == 0;
            registers[r1] = res.value;
            clocks = 1;
        } else if ((instruction & 0xFC00) == 0x2800) {
            // OR
            //puts("OR");
            const u16 r2 = (instruction & 0xF) | ((instruction & 0x200) >> 5);
            const u16 r1 = (instruction & 0x1F0) >> 4;
            const Status R2 = {.value = registers[r2]};
            const Status R1 = {.value = registers[r1]};
            const Status res = {.value = R2.value | R1.value};
            sreg->N = res._7;
            sreg->V = 0;
            sreg->S = sreg->N ^ sreg->V;
            sreg->Z = res.value == 0;
            registers[r1] = res.value;
            clocks = 1;
        } else if ((instruction & 0xFC00) == 0x2C00) {
            // MOV
            //puts("MOV");
            const u16 r2 = (instruction & 0xF) | ((instruction & 0x200) >> 5);
            const u16 r1 = (instruction & 0x1F0) >> 4;
            registers[r1] = registers[r2];
            clocks = 1;
        } else if ((instruction & 0xF000) == 0x3000) {
            // CPI
            //puts("CPI");
            const u16 value = ((instruction >> 4) & 0xF0) + (instruction & 0xF);
            const u16 reg = ((instruction >> 4) & 0xF) + 16;
            const Status R1 = {.value = registers[reg]};
            const Status K = {.value = value};
            const Status res = {.value = R1.value - K.value};
            //printf("%u \n", res.value);
            sreg->H = !R1._3&K._3 | K._3&res._3 | res._3&!R1._3;
            sreg->N = res._7;
            sreg->V = R1._7&!K._7&!res._7 | !R1._7&K._7&res._7;
            sreg->S = sreg->N ^ sreg->V;
            sreg->Z = !res.value;
            sreg->C = !R1._7&K._7 | K._7&res._7 | res._7*!R1._7;
            clocks = 1;
        } else if ((instruction & 0xF000) == 0x4000) {
            // SBCI
            //puts("SBCI");
            const u16 value = ((instruction >> 4) & 0xF0) + (instruction & 0xF);
            const u16 reg = ((instruction >> 4) & 0xF) + 16;
            const Status R1 = {.value = registers[reg]};
            const Status K = {.value = value};
            const Status res = {.value = R1.value - K.value - sreg->C};
            sreg->H = !R1._3&K._3 | K._3&res._3 | res._3&!R1._3;
            sreg->N = res._7;
            sreg->V = R1._7&!K._7&!res._7 | !R1._7&K._7&res._7;
            sreg->S = sreg->N ^ sreg->V;
            sreg->Z = res.value ? 0 : sreg->Z;
            sreg->C = !R1._7&K._7 | K._7&res._7 | res._7*!R1._7;
            registers[reg] = res.value;
            clocks = 1;
        } else if ((instruction & 0xF000) == 0x5000) {
            // SUBI
            //puts("SUBI");
            const u16 value = ((instruction >> 4) & 0xF0) + (instruction & 0xF);
            const u16 reg = ((instruction >> 4) & 0xF) + 16;
            const Status R1 = {.value = registers[reg]};
            const Status K = {.value = value};
            const Status res = {.value = R1.value - K.value};
            //printf("(reg: %d) %02x - %02x = ", reg, R1.value, K.value);
            sreg->H = !R1._3&K._3 | K._3&res._3 | res._3&!R1._3;
            sreg->N = res._7;
            sreg->V = R1._7&!K._7&!res._7 | !R1._7&K._7&res._7;
            sreg->S = sreg->N ^ sreg->V;
            sreg->Z = res.value ? 0 : sreg->Z;
            sreg->C = !R1._7&K._7 | K._7&res._7 | res._7*!R1._7;
            registers[reg] = res.value;
            //printf("%02x\n", registers[reg]);
            clocks = 1;
        } else if ((instruction & 0xF000) == 0x6000) {
            // ORI/SBR
            const u16 value = ((instruction >> 4) & 0xF0) + (instruction & 0xF);
            const u16 reg = ((instruction >> 4) & 0xF) + 16;
            const Status R1 = {.value = registers[reg]};
            const Status K = {.value = value};
            const Status res = {.value = R1.value | K.value};
            sreg->N = res._7;
            sreg->V = 0;
            sreg->S = sreg->N ^ sreg->V;
            sreg->Z = res.value == 0;
            registers[reg] = res.value;
            clocks = 1;
        } else if ((instruction & 0xF000) == 0x7000) {
            // ANDI/CBR
            const u16 value = ((instruction >> 4) & 0xF0) + (instruction & 0xF);
            const u16 reg = ((instruction >> 4) & 0xF) + 16;
            const Status R1 = {.value = registers[reg]};
            const Status K = {.value = value};
            const Status res = {.value = R1.value & K.value};
            sreg->N = res._7;
            sreg->V = 0;
            sreg->S = sreg->N ^ sreg->V;
            sreg->Z = res.value == 0;
            registers[reg] = res.value;
            clocks = 1;
        } else if ((instruction & 0xD000) == 0x8000) {
            // LDD/STD Rd through Z+k or Y+k
            const u16 reg = (instruction & 0x01F0) >> 4;
            const u16 value = (instruction & 0x7) | ((instruction >> 7) & 0x0018) | ((instruction >> 7) & 0x0020);
            u16 *YZ = instruction & 0x0008 ? Y : Z;
            if (instruction & 0x0200) {
                // STD
                SRAM[*YZ+value] = registers[reg];
            } else {
                // LDD
                registers[reg] = SRAM[*YZ+value];
            }
            clocks = 2;
        } else if ((instruction & 0xFC0F) == 0x9000) {
            // LDS rd,i/STS i,rd
            print_address = flash16[++pc];
            const u16 reg = instruction & 0x003F;
            if (instruction & 0x0200) {
                // STS
                SRAM[print_address] = registers[reg];
            } else {
                // LDS
                registers[reg] = SRAM[print_address];
            }
            clocks = 2;
        } else if ((instruction & 0xFC07) == 0x9001) {
            // LD/ST Rd through Z+/Y+
            const u16 reg = (instruction & 0x01F0) >> 4;
            u16 *YZ = instruction & 0x0008 ? Y : Z;
            if (instruction & 0x0200) {
                // ST
                SRAM[*YZ++] = registers[reg];
            } else {
                // LD
                registers[reg] = SRAM[*YZ++];
            }
            clocks = 2;
        } else if ((instruction & 0xFC07) == 0x9002) {
            // LD/ST Rd through −Z/−Y
            const u16 reg = (instruction & 0x01F0) >> 4;
            u16 *YZ = instruction & 0x0008 ? Y : Z;
            if (instruction & 0x0200) {
                // ST
                SRAM[--*YZ] = registers[reg];
            } else {
                // LD
                registers[reg] = SRAM[--*YZ];
            }
            clocks = 3;
        } else if ((instruction & 0xFE0D) == 0x9004) {
            // LPM/ELPM Rd,Z
            NOT_IMPL;
            clocks = 3;
        } else if ((instruction & 0xFE0D) == 0x9005) {
            // LPM/ELPM Rd,Z+
            NOT_IMPL;
            clocks = 3;
        } else if ((instruction & 0xFE0F) == 0x9204) {
            // XCH Z,Rd
            const u16 reg = (instruction & 0x01F0) >> 4;
            u8 tmp = SRAM[*Z];
            SRAM[*Z] = registers[reg];
            registers[reg] = tmp;
            clocks = 2;
        } else if ((instruction & 0xFE0F) == 0x9205) {
            // LAS Z,Rd
            const u16 reg = (instruction & 0x01F0) >> 4;
            u8 tmp = SRAM[*Z];
            SRAM[*Z] |= registers[reg];
            registers[reg] = tmp;
            clocks = 2;
        } else if ((instruction & 0xFE0F) == 0x9206) {
            // LAC Z,Rd
            const u16 reg = (instruction & 0x01F0) >> 4;
            u8 tmp = SRAM[*Z];
            SRAM[*Z] &= (0xFF-registers[reg]);
            registers[reg] = tmp;
            clocks = 2;
        } else if ((instruction & 0xFE0F) == 0x9207) {
            // LAT Z,Rd
            const u16 reg = (instruction & 0x01F0) >> 4;
            u8 tmp = SRAM[*Z];
            SRAM[*Z] ^= registers[reg];
            registers[reg] = tmp;
            clocks = 2;
        } else if ((instruction & 0xFC0F) == 0x900C) {
            // LD/ST Rd through X
            const u16 reg = (instruction & 0x01F0) >> 4;
            if (instruction & 0x0200) {
                // ST
                SRAM[*X] = registers[reg];
            } else {
                // LD
                registers[reg] = SRAM[*X];
            }
            clocks = 1;
        } else if ((instruction & 0xFC0F) == 0x900D) {
            // LD/ST Rd through X+
            const u16 reg = (instruction & 0x01F0) >> 4;
            if (instruction & 0x0200) {
                // ST
                SRAM[*X++] = registers[reg];
            } else {
                // LD
                registers[reg] = SRAM[*X++];
            }
            clocks = 2;
        } else if ((instruction & 0xFC0F) == 0x900E) {
            // LD/ST Rd through -X
            const u16 reg = (instruction & 0x01F0) >> 4;
            if (instruction & 0x0200) {
                // ST
                SRAM[--*X] = registers[reg];
            } else {
                // LD
                registers[reg] = SRAM[--*X];
            }
            clocks = 3;
        } else if ((instruction & 0xFC0F) == 0x900F) {
            // POP/PUSH Rd
            const u16 reg = (instruction & 0x01F0) >> 4;
            if (instruction & 0x0200) {
                // PUSH
                SRAM[--*sp] = registers[reg];
            } else {
                // POP
                registers[reg] = SRAM[(*sp)++];
            }
            clocks = 2;
        } else if ((instruction & 0xFE0F) == 0x9400) {
            // COM Rd
            const u16 reg = (instruction & 0x01F0) >> 4;
            const Status R1 = {.value = registers[reg]};
            const Status res = {.value = ~R1.value};
            sreg->N = res._7;
            sreg->V = 0;
            sreg->S = sreg->N ^ sreg->V;
            sreg->Z = res.value ? 0 : sreg->Z;
            sreg->C = 1;
            registers[reg] = res.value;
            clocks = 1;
        } else if ((instruction & 0xFE0F) == 0x9401) {
            // NEG Rd
            const u16 reg = (instruction & 0x01F0) >> 4;
            const Status R1 = {.value = registers[reg]};
            const Status res = {.value = -R1.value};
            sreg->H = R1._3 | res._3;
            // TODO(mdizdar): sreg->H = /*P._3 + !R1._3; what the fuck is P???*/;
            sreg->N = res._7;
            sreg->V = res.value == 0x80;
            sreg->S = sreg->N ^ sreg->V;
            sreg->Z = res.value ? 0 : sreg->Z;
            sreg->C = !!res.value;
            registers[reg] = res.value;
            clocks = 1;
        } else if ((instruction & 0xFE0F) == 0x9402) {
            // SWAP Rd
            const u16 reg = (instruction & 0x01F0) >> 4;
            registers[reg] = (registers[reg] >> 4) | ((registers[reg] & 0x0F) << 4);
            clocks = 1;
        } else if ((instruction & 0xFE0F) == 0x9403) {
            // INC Rd
            const u16 reg = (instruction & 0x01F0) >> 4;
            const Status res = {.value = registers[reg]+1};
            sreg->N = res._7;
            sreg->V = res.value == 0x80;
            sreg->S = sreg->N ^ sreg->V;
            sreg->Z = res.value ? 0 : sreg->Z;
            registers[reg] = res.value;
            clocks = 1;
        } else if ((instruction & 0xFE0F) == 0x9405) {
            // ASR Rd
            const u16 reg = (instruction & 0x01F0) >> 4;
            const Status res = {.value = (registers[reg]>>1) | (registers[reg]&0x80)};
            sreg->N = res._7;
            sreg->C = registers[reg]&1;
            sreg->V = sreg->N ^ sreg->C;
            sreg->S = sreg->N ^ sreg->V;
            sreg->Z = res.value ? 0 : sreg->Z;
            registers[reg] = res.value;
            clocks = 1;
        } else if ((instruction & 0xFE0F) == 0x9406) {
            // LSR Rd
            const u16 reg = (instruction & 0x01F0) >> 4;
            const Status res = {.value = registers[reg] >> 1};
            sreg->N = 0;
            sreg->C = registers[reg]&1;
            sreg->V = sreg->N ^ sreg->C;
            sreg->S = sreg->N ^ sreg->V;
            sreg->Z = res.value ? 0 : sreg->Z;
            registers[reg] = res.value;
            clocks = 1;
        } else if ((instruction & 0xFE0F) == 0x9407) {
            // ROR Rd
            const u16 reg = (instruction & 0x01F0) >> 4;
            const Status res = {.value = (registers[reg]>>1) | (sreg->C ? 0x80 : 0)};
            sreg->N = res._7;
            sreg->C = registers[reg]&1;
            sreg->V = sreg->N ^ sreg->C;
            sreg->S = sreg->N ^ sreg->V;
            sreg->Z = res.value ? 0 : sreg->Z;
            registers[reg] = res.value;
            clocks = 1;
        } else if ((instruction & 0xFF0F) == 0x9408) {
            // SEx/CLx Status register clear/set bit
            const u16 bit = (instruction & 0x0070) >> 4;
            if ((instruction & 0x0080) >> 7) {
                // clear
                sreg->value &= ~(1 << bit);
            } else {
                // set
                sreg->value |= 1 << bit;
            }
            clocks = 1;
        } else if (instruction == 0x9508) {
            // RET
            pc = SRAM[*sp]-1;
            *sp += 2;
            clocks = 4;
        } else if (instruction == 0x9518) {
            // RETI
            pc = SRAM[*sp]-1;
            *sp += 2;
            sreg->I = 1;
            clocks = 4;
        } else if (instruction == 0x9588) {
            // SLEEP
            NOT_IMPL;
            // TODO(mdizdar): idk what this does yet
            clocks = 1;
        } else if (instruction == 0x9598) {
            // BREAK
            NOT_IMPL;
            // TODO(mdizdar): use this to enter step by step mode?
            clocks = 1;
        } else if (instruction == 0x95A8) {
            // WDR
            NOT_IMPL;
            // TODO(mdizdar): does something to some timer idk
            clocks = 1;
        } else if (instruction == 0x95C8) {
            // LPM
            // TODO(mdizdar): check that this works as intended, I'm not sure that the semantics of lower/higher byte are being respected
            registers[0] = flash[*Z];
            clocks = 3;
        } else if (instruction == 0x95D8) {
            // ELPM
            NOT_IMPL;
            clocks = 3;
        } else if (instruction == 0x95E8) {
            // SPM
            NOT_IMPL;
            // TODO(mdizdar): not applicable I guess
        } else if (instruction == 0x95F8) {
            // SPM+
            NOT_IMPL;
            // TODO(mdizdar): not applicable I guess
        } else if ((instruction & 0xFEEF) == 0x9409) {
            // Indirect jump/call to Z or EIND:Z
            const u16 address = *Z;
            if (instruction & 0x0002) {
                // CALL
                SRAM[*sp -= 2] = pc+1;
                pc = address-1;
                clocks = 3;
            } else {
                // JMP
                pc = address-1;
                clocks = 2;
            }
        } else if ((instruction & 0xFE0F) == 0x940A) {
            // DEC Rd
            const u16 reg = (instruction & 0x01F0) >> 4;
            const Status res = {.value = registers[reg]-1};
            sreg->N = res._7;
            sreg->V = registers[reg] == 0x80;
            sreg->S = sreg->N ^ sreg->V;
            sreg->Z = res.value ? 0 : sreg->Z;
            registers[reg] = res.value;
            clocks = 1;
        } else if ((instruction & 0xFF0F) == 0x940B) {
            // DES round k
            NOT_IMPL;
            // TODO(mdizdar): clocks = 1;
        } else if ((instruction & 0xFE0C) == 0x940C) {
            // JMP/CALL abs22
            const u16 hi = flash16[++pc];
            print_address = hi;
            const u32 address = hi | ((instruction & 0x01F0) << 14) | ((instruction & 0x0001) << 16);
            if (instruction & 0x0002) {
                // CALL
                SRAM[*sp -= 2] = pc+1;
                pc = address-1;
                clocks = 4;
            } else {
                // JMP
                pc = address-1;
                clocks = 3;
            }
        } else if ((instruction & 0xFF00) == 0x9600) {
            // ADIW Rp,uimm6
            const u8 value = (instruction & 0x000F) | ((instruction & 0x00C0) >> 2);
            const u8 reg = (((instruction & 0x0030) >> 4)+12)*2;
            u16 *reg_pair = (u16 *)&registers[reg];
            union {
                struct {
                    Status hi, lo;
                };
                u16 value;
            } R1 = {.value = *reg_pair}, res = {.value = *reg_pair+value};
            sreg->C = !res.hi._7 & R1.hi._7;
            sreg->Z = res.value == 0;
            sreg->N = res.hi._7;
            sreg->V = !R1.hi._7 & res.hi._7;
            sreg->S = sreg->V ^ sreg-> N;
            *reg_pair = res.value;
            clocks = 2;
        } else if ((instruction & 0xFF00) == 0x9700) {
            // SBIW Rp,uimm6
            const u8 value = (instruction & 0x000F) | ((instruction & 0x00C0) >> 2);
            const u8 reg = (((instruction & 0x0030) >> 4)+12)*2;
            u16 *reg_pair = (u16 *)&registers[reg];
            union {
                struct {
                    Status hi, lo;
                };
                u16 value;
            } R1 = {.value = *reg_pair}, res = {.value = *reg_pair-value};
            sreg->C = !res.hi._7 & R1.hi._7;
            sreg->Z = res.value == 0;
            sreg->N = res.hi._7;
            sreg->V = !R1.hi._7 & res.hi._7;
            sreg->S = sreg->V ^ sreg-> N;
            *reg_pair = res.value;
            clocks = 2;
        } else if ((instruction & 0xFD00) == 0x9800) {
            // CBI/SBI a,b (clear/set I/O bit)
            const u8 value = (instruction & 0x00F8) >> 3;
            const u8 bit = instruction & 0x7;
            if (instruction & 0x0200) {
                // CBI
                IO_registers[value] &= ~(1 << bit);
            } else {
                // SBI
                IO_registers[value] |= 1 << bit;
            }
            clocks = 2;
        } else if ((instruction & 0xFD00) == 0x9900) {
            // SBIC/SBIS a,b (I/O bit test)
            const u8 value = (instruction & 0x00F8) >> 3;
            const u8 bit = instruction & 0x7;
            clocks = 1;
            if (((instruction & 0x0200) >> 9) == ((IO_registers[value] >> bit) & 1)) {
                u16 next_instruction = flash16[pc+1];
                if ((instruction & 0xFC0F) == 0x9000 || (instruction & 0xFE0C) == 0x940C) {
                    clocks = 3;
                    pc += 2;
                } else {
                    clocks = 2;
                    ++pc;
                }
            }
        } else if ((instruction & 0xFC00) == 0x9C00) {
            // MUL, unsigned: R1:R0 = Rr × Rd
            const u16 r1 = (instruction & 0xF) | ((instruction & 0x200) >> 5);
            const u16 r2 = (instruction & 0x1F0) >> 4;
            u8 *R1 = &registers[r1];
            u8 *R2 = &registers[r2];
            u16 *res = (u16 *)&registers[0];
            *res = *R1 * *R2;
            sreg->Z = !*res;
            sreg->C = (*res) >> 15;
            clocks = 2;
        } else if ((instruction & 0xF000) == 0xB000) {
            // IN/OUT to I/O space
            const u16 address = (instruction & 0xF) | ((instruction & 0x600) >> 5);
            const u16 reg = (instruction & 0x1F0) >> 4;
            if (instruction & 0x0800) {
                // OUT
                IO_space[address] = registers[reg];
            } else {
                // IN
                registers[reg] = IO_space[address];
            }
            clocks = 1;
        } else if ((instruction & 0xE000) == 0xC000) {
            // RJMP/RCALL to PC + simm12
            s16 offset = instruction & 0x0FFF;
            if (offset & 0x0800) {
                offset -= 1 << 12;
            }
            if (instruction & 0x1000) {
                // RCALL
                SRAM[*sp -= 2] = pc+1;
                pc += offset;
            } else {
                // RJMP
                pc += offset;
            }
            clocks = 3;
        } else if ((instruction & 0xF000) == 0xE000) {
            // LDI Rd,K
            const u16 value = ((instruction >> 4) & 0xF0) + (instruction & 0xF);
            const u16 reg = ((instruction >> 4) & 0xF) + 16;
            registers[reg] = value;
            clocks = 1;
        } else if ((instruction & 0xF800) == 0xF000) {
            // Conditional branch on status register bit
            s8 offset = (s8)((instruction & 0x03F8) >> 3);
            if (offset & 0x40) {
                offset -= 1 << 7;
            }
            u8 bit = instruction & 0x7;
            clocks = 1;
            if (instruction & 0x0400) {
                // branch if bit is clear
                if (!(sreg->value & (1 << bit))) {
                    pc += offset;
                    clocks = 2;
                }
            } else {
                // branch if bit is set
                if (sreg->value & (1 << bit)) {
                    pc += offset;
                    clocks = 2;
                }
            }
        } else if ((instruction & 0xFC08) == 0xF800) {
            // BLD/BST register bit to STATUS.T
            const u8 bit = (instruction & 0x7);
            const u16 reg = (instruction >> 4) & 0xF;
            if (instruction & 0x0200) {
                // BST
                sreg->T = (registers[reg] >> bit) & 1;
            } else {
                // BLD
                if (sreg->T) {
                    registers[reg] |= (1 << bit);
                }
            }
            clocks = 1;
        } else if ((instruction & 0xFC08) == 0xFC00) {
            // SBRC/SBRS skip if register bit equals B
            const u8 bit = (instruction & 0x7);
            const u16 reg = (instruction >> 4) & 0xF;
            clocks = 1;
            if (((instruction & 0x0200) >> 9) == ((registers[reg] >> bit) & 1)) {
                u16 next_instruction = flash16[pc+1];
                if ((instruction & 0xFC0F) == 0x9000 || (instruction & 0xFE0C) == 0x940C) {
                    clocks = 3;
                    pc += 2;
                } else {
                    clocks = 2;
                    ++pc;
                }
            }
        } else {
            error(-1, "unrecognized instruction 0x%04X", instruction);
            clocks = 1;
        }
#ifdef DEBUG
        print_AVR_instruction(instruction, print_address);
#endif //DEBUG
        total_clocks += clocks;
    }
    return 0;
}
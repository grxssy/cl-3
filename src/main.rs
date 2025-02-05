/*
#####################################################################
#                                                                   #
#                             CRABLET-3                             #
#                        AN LC-3 VM IN Rust                         #
#                                                                   #
#       I've tried to avoid global variables and static mut as      #
#       much as possible. The exceptions to this are MEMORY_MAX,    #
#       MEMORY and the starting postiong. I made this choice as     #
#       I felt that treating memory as an oracle / undefined        #
#       behaviour is closer to the physical workings of memory.     #
#                                                                   #
#       The register on the other hand are local and can all be     #
#       accessed by reference in the opcode instructions.           #
#       This greatly reduces the need for unsafe operations.        #
#                                                                   #
#       There is a decent amount of C mixed in at this stage.       #
#       Some stuff I simply couldn't figure out how to implement    #
#       in pure Rust.                                               #
#                                                                   #
#       This was an eductational excercise and my first time        #
#       working with both rust and systems programming. This        #
#       is a work in progress and will be revisited and             #
#       improved upon                                               #
#       If there is any strange behaviour, poor implementations,    #
#       misguided ideas, or otherwise bad Rust in this code         #
#       feedback is welcome and appreciated                         #
#                                                                   #
#####################################################################
*/

use libc::{
    fd_set, select, signal, tcgetattr, tcsetattr, termios, timeval, ECHO, FD_SET, FD_ZERO, ICANON,
    SIGINT, STDIN_FILENO, TCSANOW,
};
use std::fs::File;
use std::io::{stdin, Read, Write};
use std::process::exit;

/*
#############################################
#                                           #
#           HARDWARE COMPONENTS             #
#                                           #
#      Defines all of the registers,        #
#      opcodes, memory, condition_flags     #
#      and memory mapped registers          #
#                                           #
#      Note: Casting a u(n) as usize is     #
#      unsafe as it can truncate bits       #
#      on smaller architectures.            #
#      Don't run this on anyhtng with       #
#      less than 16 bits.                   #
#                                           #
#############################################
*/

// Memory
const MEMORY_MAX: u16 = u16::MAX;
static mut MEMORY: [u16; MEMORY_MAX as usize] = [0; MEMORY_MAX as usize];

const PC_START: u16 = 0x3000;

// Registers
#[allow(dead_code)]
#[repr(u16)]
enum Register {
    RR0 = 0,
    RR1,
    RR2,
    RR3,
    RR4,
    RR5,
    RR6,
    RR7,
    RPc,
    RCond,
    RCount,
}

/// A type for passing around registers to avoid global state
type RegisterStore = [u16; Register::RCount as usize];

// Memory Mapped Registers
#[repr(u16)]
enum MMR {
    MrKbsr = 0xFE00,
    MrKbdr = 0xFE02,
}

// Opcodes
#[allow(dead_code)]
#[repr(u16)]
enum OpCode {
    OpBr = 0,
    OpAdd,
    OpLd,
    OpSt,
    OpJsr,
    OpAnd,
    OpLdr,
    OpStr,
    OpRti,
    OpNot,
    OpLdi,
    OpSti,
    OpJmp,
    OpRes,
    OpLea,
    OpTrap,
}

// Condition Flags
#[allow(dead_code)]
#[repr(u16)]
enum ConditionFlag {
    FlPos = 1 << 0, /* P */
    FlZro = 1 << 1, /* Z */
    FlNeg = 1 << 2, /* N */
}

/*
#############################################
#                                           #
#                TRAP CODES                 #
#                                           #
#      Defines the calling conventions      #
#      for the fictitout OS's               #
#      "System Calls" that this VM runs     #
#      this VM runs.                        #
#                                           #
#      Only handles basic IO and is         #
#      mostly implemented in high level     #
#      Rust.                                #
#                                           #
#############################################
*/

// TRAP Codes
#[allow(dead_code)]
#[repr(u16)]
enum TrapCode {
    TrapGetC = 0x20, // Get character from keyboard, not echoed
    TrapOut,         // Output a character
    TrapPuts,        // Output a word string
    TrapIn,          // Get character from keyboard, echoed
    TrapPutSp,       // Output a byte string
    TrapHalt,        // Halt the program
}

/*
##########################################
#                                        #
#              Virtual Machine           #
#                                        #
#     Reads, loads, and runs an LC-3     #
#     obj file.                          #
#                                        #
#     Handles interrupts and input       #
#     buffering via C externs.           #
#                                        #
#                                        #
##########################################
*/

fn main() {
    /* LOAD IMAGE */
    let args: Vec<String> = std::env::args().collect();
    read_image(&args[1]);

    /* SETUP VM */

    let handle_interrupt_ptr = (handle_interrupt as usize) as *const ();
    unsafe {
        signal(SIGINT, handle_interrupt_ptr as usize);
        disable_input_buffering()
    };

    let mut reg: RegisterStore = [0; Register::RCount as usize];
    reg[Register::RCond as usize] = ConditionFlag::FlZro as u16;
    reg[Register::RPc as usize] = PC_START;

    let mut running: bool = true;

    /* MAIN LOOP */

    while running {
        // Fetch instruction from memory
        let instr: u16 = mem_read(reg[Register::RPc as usize]);

        // Increment the process counter
        reg[Register::RPc as usize] += 1;

        // Get the opcode
        let raw_op: u16 = instr >> 12;
        assert!(raw_op <= OpCode::OpTrap as u16, "Bad Op");
        let op = unsafe { std::mem::transmute(raw_op) };

        // Get the Operation
        match op {
            OpCode::OpAdd => add(&instr, &mut reg),
            OpCode::OpAnd => and(&instr, &mut reg),
            OpCode::OpNot => not(&instr, &mut reg),
            OpCode::OpBr => br(&instr, &mut reg),
            OpCode::OpJmp => jmp(&instr, &mut reg),
            OpCode::OpJsr => jsr(&instr, &mut reg),
            OpCode::OpLd => ld(&instr, &mut reg),
            OpCode::OpLdi => ldi(&instr, &mut reg),
            OpCode::OpLdr => ldr(&instr, &mut reg),
            OpCode::OpLea => lea(&instr, &mut reg),
            OpCode::OpSt => st(&instr, &mut reg),
            OpCode::OpSti => sti(&instr, &mut reg),
            OpCode::OpStr => str(&instr, &mut reg),
            OpCode::OpTrap => trap(&instr, &mut reg, &mut running),
            OpCode::OpRes => res(),
            OpCode::OpRti => rti(),
        }
    }

    /* SHUTDOWN */
    unsafe { restore_input_buffering() };
}

fn handle_interrupt() {
    unsafe { restore_input_buffering() };
    println!();
    exit(-2);
}

/*
##########################################
#                                        #
#              Image Loading             #
#                                        #
##########################################
*/

fn read_image_file(file: &mut File) {
    let mut buffer = vec![0u8; 2];

    file.read_exact(&mut buffer).expect("Couldn't read file");
    // LC-3 is big endian
    // My system is little endian

    let origin = u16::from_le(((buffer[0] as u16) << 8) | buffer[1] as u16);

    let mut mem_ptr: *mut u16 = unsafe { MEMORY.as_mut_ptr().offset(origin as isize) };

    assert!((mem_ptr as u16) < MEMORY_MAX);

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Couldn't read file");

    for chunk in buffer.chunks(2) {
        unsafe {
            *mem_ptr = u16::from_le(((chunk[0] as u16) << 8) | chunk[1] as u16);
            mem_ptr = mem_ptr.offset(1);
        };
    }
}

fn read_image(path: &String) {
    let mut file: File = File::open(path).unwrap();

    read_image_file(&mut file);
}

/*
##########################################
#                                        #
#            Memory Operations           #
#                                        #
##########################################
*/

fn mem_write(address: u16, val: u16) {
    assert!(address < MEMORY_MAX);

    unsafe { MEMORY[address as usize] = val };
}

fn mem_read(address: u16) -> u16 {
    assert!(address < MEMORY_MAX);

    if address == MMR::MrKbsr as u16 {
        assert!((MMR::MrKbsr as u16) < (MEMORY_MAX));
        assert!((MMR::MrKbdr as u16) < (MEMORY_MAX));
        unsafe {
            if check_key() {
                MEMORY[MMR::MrKbsr as usize] = 1 << 15;
                MEMORY[MMR::MrKbdr as usize] = get_char() as u16
            } else {
                MEMORY[MMR::MrKbsr as usize] = 0;
            }
        }
    }
    unsafe { MEMORY[address as usize] }
}

static mut ORIGINAL_TIO: termios = unsafe { std::mem::zeroed() };

/*
##########################################
#                                        #
#             Input Buffering            #
#                                        #
##########################################
*/

unsafe fn disable_input_buffering() {
    if tcgetattr(STDIN_FILENO, &mut ORIGINAL_TIO) != 0 {
        panic!("Failed to get terminal attributes");
    }

    let mut new_tio = ORIGINAL_TIO;

    new_tio.c_lflag &= !(ICANON | ECHO);

    if tcsetattr(STDIN_FILENO, TCSANOW, &new_tio) != 0 {
        panic!("Failed to set terminal attributes");
    }
}

unsafe fn restore_input_buffering() {
    tcsetattr(STDIN_FILENO, TCSANOW, &ORIGINAL_TIO);
}

unsafe fn check_key() -> bool {
    let mut readfds: fd_set = std::mem::zeroed();
    FD_ZERO(&mut readfds);
    FD_SET(STDIN_FILENO, &mut readfds);

    let mut timeout = timeval {
        tv_sec: 0,
        tv_usec: 0,
    };

    select(
        1,
        &mut readfds,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut timeout,
    ) != 0
}

/*
##########################################
#                                        #
#                Opcodes                 #
#                                        #
##########################################
*/

/// Extends the immediate value to 16 bits
fn sign_extend(mut value: u16, bits: u16) -> u16 {
    let sign: u16 = value >> (bits - 1);

    if sign != 0 {
        value |= (0xFFFF as u16) << (bits - 1);
    }
    return value;
}

/// Updates the flag register
fn update_flags(r: u16, reg: &mut RegisterStore) {
    if reg[r as usize] == 0 {
        reg[Register::RCond as usize] = ConditionFlag::FlZro as u16
    } else if reg[r as usize] >> 15 == 1 {
        reg[Register::RCond as usize] = ConditionFlag::FlNeg as u16
    } else {
        reg[Register::RCond as usize] = ConditionFlag::FlPos as u16
    }
}

/// **Instruction: ADD - Addition**
/// Assembler Formats
/// `ADD DR, SR1, SR2`
/// `ADD DR, SR1, imm5`
fn add(instr: &u16, reg: &mut RegisterStore) {
    // Destination register
    let dr: u16 = (instr >> 9) & 0x7;

    // Source register
    let sr1: u16 = (instr >> 6) & 0x7;

    // Immediate flag
    let i_flag = (instr >> 5) & 0x1;

    if i_flag != 0 {
        // Get immediate value
        let imm5 = sign_extend(instr & 0x1F, 5);

        reg[dr as usize] = reg[sr1 as usize].wrapping_add(imm5);
    } else {
        // Second operand
        let sr2: u16 = instr & 0x7;
        reg[dr as usize] = reg[sr1 as usize].wrapping_add(reg[sr2 as usize]);
    }
    update_flags(dr, reg);
}

/// **Instruction: AND - Bit-wise Logical AND**
/// Assembler Formats
/// `AND DR, SR1, SR2`
/// `AND DR, SR1, imm5`
fn and(instr: &u16, reg: &mut RegisterStore) {
    // Destination Register
    let dr: u16 = (instr >> 9) & 0x7;

    // Source register
    let sr1: u16 = (instr >> 6) & 0x7;

    // Immediate flag
    let i_flag = (instr >> 5) & 0x1;

    if i_flag != 0 {
        // Get immediate value
        let imm5 = sign_extend(instr & 0x1F, 5);

        reg[dr as usize] = reg[sr1 as usize] & imm5;
    } else {
        // Source register
        let sr2: u16 = instr & 0x7;

        reg[dr as usize] = reg[sr1 as usize] & reg[sr2 as usize];
    }
    update_flags(dr, reg);
}

/// **Instruction: NOT - Bit-Wise Complement**
/// Assembler Format
/// `NOT DR, SR`
fn not(instr: &u16, reg: &mut RegisterStore) {
    // Destination Register
    let dr: u16 = (instr >> 9) & 0x7;

    // Source Register
    let sr: u16 = (instr >> 6) & 0x7;

    reg[dr as usize] = !reg[sr as usize];

    update_flags(dr, reg);
}

/// **Instruction: BR - Conditional Branch**
/// Assembler Formats
/// `Brn LABEL`
/// `BRz LABEL`
/// `BRp LABEL`
/// `BR* LABEL`
/// `BRzp LABEL`
/// `BRnp LABEL`
/// `BRnz LABEL`
/// `BRnzp LABEL`
fn br(instr: &u16, reg: &mut RegisterStore) {
    // PC Offset
    let offset: u16 = sign_extend(instr & 0x1FF, 9);

    // Condition flag
    let c_flag = (instr >> 9) & 0x7;

    if c_flag & (reg[Register::RCond as usize] as u16) != 0 {
        reg[Register::RPc as usize] = reg[Register::RPc as usize].wrapping_add(offset);
    }
}
/// **Instruction: JMP - Unconditional Branch**
/// **Instruction: RET - Unconditional Return**
/// Assembler Formats
/// `JMP BaseR`
/// `RET`
fn jmp(instr: &u16, reg: &mut RegisterStore) {
    // Base Register
    let base_r: u16 = instr >> 6 & 0x7;

    // Set program counter
    reg[Register::RPc as usize] = reg[base_r as usize];
}

/// **Instruction: JSR / JSRR - Jump to Subroutine**
/// Assembler Formats
/// `JSR LABEL`
/// `JSRR BaseR`
fn jsr(instr: &u16, reg: &mut RegisterStore) {
    // Condition Flag
    let c_flag: u16 = (instr >> 11) & 1;

    reg[Register::RR7 as usize] = reg[Register::RPc as usize];

    if c_flag != 0 {
        // Offset
        let offset11: u16 = sign_extend(instr & 0x7FF, 11);
        reg[Register::RPc as usize] = (reg[Register::RPc as usize] as u16).wrapping_add(offset11);
    } else {
        // Base Register
        let base_r = (instr >> 6) & 0x7;
        reg[Register::RPc as usize] = reg[base_r as usize];
    }
}

/// **Instruction: LD - Load Direct**
/// Assembler Format
/// `LD DR, LABEL`
fn ld(instr: &u16, reg: &mut RegisterStore) {
    // Destination Register
    let dr: u16 = (instr >> 9) & 0x7;

    // PC Offset
    let offset9: u16 = sign_extend(instr & 0x1FF, 9);

    // Load into destination register from memory
    reg[dr as usize] = mem_read(reg[Register::RPc as usize].wrapping_add(offset9));

    update_flags(dr, reg);
}

/// **Instruction: LDI - Load Indirect**
/// Assembler Format
/// `LDI DR, LABEL`
fn ldi(instr: &u16, reg: &mut RegisterStore) {
    // Destination Register
    let dr: u16 = (instr >> 9) & 0x7;

    // Offset
    let offset9 = sign_extend(instr & 0x1FF, 9);

    // Load into destination register from memory(memory)
    reg[dr as usize] = mem_read(mem_read(reg[Register::RPc as usize].wrapping_add(offset9)));

    update_flags(dr, reg);
}

/// **Instruction: LDR - Load Register**
/// Assembler Format
/// `LDR DR, BaseR, offset6`
fn ldr(instr: &u16, reg: &mut RegisterStore) {
    // Destination Register
    let dr: u16 = (instr >> 9) & 0x7;

    // BaseR
    let base_r: u16 = (instr >> 6) & 0x7;

    // Offset
    let offset6: u16 = sign_extend(instr & 0x3F, 6);

    // Load into destination register from memory
    reg[dr as usize] = mem_read(reg[base_r as usize].wrapping_add(offset6));

    update_flags(dr, reg);
}

/// **Instruction: LEA - Load Effective Address**
/// Assembler Format
/// `LEA DR, LABEL`
fn lea(instr: &u16, reg: &mut RegisterStore) {
    // Destination Regsiter
    let dr: u16 = (instr >> 9) & 0x7;

    // Offset
    let offset9: u16 = sign_extend(instr & 0x1FF, 9);

    reg[dr as usize] = reg[Register::RPc as usize].wrapping_add(offset9);

    update_flags(dr, reg);
}

/// **Instruction: ST - Store**
/// Assembler Format
/// `ST SR, LABEL`
fn st(instr: &u16, reg: &mut RegisterStore) {
    // Source Register
    let sr: u16 = (instr >> 9) & 0x7;
    // Offset
    let offset9: u16 = sign_extend(instr & 0x1FF, 9);

    // Write to memory
    mem_write(
        reg[Register::RPc as usize].wrapping_add(offset9),
        reg[sr as usize],
    );
}

/// **Instruction: STI - Store Indirect**
/// Assembler Format
/// `STI SR, LABEL`
fn sti(instr: &u16, reg: &mut RegisterStore) {
    // Source Register
    let sr: u16 = (instr >> 9) & 0x7;

    // Offset
    let offset9: u16 = sign_extend(instr & 0x1FF, 9);

    // Write to memory from read memory
    mem_write(
        mem_read(reg[Register::RPc as usize].wrapping_add(offset9)),
        reg[sr as usize],
    );
}

/// **Instruction: STR - Store Register**
/// Assembler Format
/// `STR SR, BaseR, offset6`
fn str(instr: &u16, reg: &mut RegisterStore) {
    // Register Content
    let sr: u16 = (instr >> 9) & 0x7;

    // Base
    let base_r: u16 = (instr >> 6) & 0x7;

    // Offset
    let offset6: u16 = sign_extend(instr & 0x3F, 6);

    // Write to memory
    mem_write(reg[base_r as usize].wrapping_add(offset6), reg[sr as usize]);
}

/// **Instruction: TRAP - System Call**
/// Assembler Format
/// `TRAP trapvector8`
fn trap(instr: &u16, reg: &mut RegisterStore, running: &mut bool) {
    let raw_trap: u16 = instr & 0xFF;

    assert!(raw_trap <= TrapCode::TrapHalt as u16);
    let trap: TrapCode = unsafe { std::mem::transmute(raw_trap) };

    reg[Register::RR7 as usize] = reg[Register::RPc as usize];

    match trap {
        TrapCode::TrapGetC => trap_getc(reg),
        TrapCode::TrapOut => trap_out(reg),
        TrapCode::TrapPuts => unsafe { trap_puts(reg) },
        TrapCode::TrapIn => trap_in(reg),
        TrapCode::TrapPutSp => unsafe { trap_putsp(reg) },
        TrapCode::TrapHalt => trap_halt(running),
    }
}

/// RESERVED
fn res() {
    panic!("Reserved Instruction: RES")
}

/// **Instruction RTI - Return from interrupt**
/// UNUSED
/// Assembler Format
/// `RTI`
fn rti() {
    panic!("Unused Instruction: RTI")
}

/// Put a character
// TODO: Find a safe way to do this
unsafe fn trap_puts(reg: &RegisterStore) {
    // Get pointer to memory offset by Register R0
    let mut c: *mut u16 = MEMORY
        .as_mut_ptr()
        .offset(reg[Register::RR0 as usize] as isize);

    // Loop through memory until the string is terminated
    while *c != 0 {
        print!("{}", (*c).to_le_bytes()[0] as char);

        // Increment the pointer
        c = c.offset(1);
    }

    std::io::stdout().flush().unwrap();
}

/// Input a character
fn trap_getc(reg: &mut RegisterStore) {
    let c: char = get_char();
    reg[Register::RR0 as usize] = c as u16;
    update_flags(Register::RR0 as u16, reg)
}

/// Output Character
fn trap_out(reg: &RegisterStore) {
    let buff = reg[Register::RR0 as usize].to_le_bytes();

    print!("{}", buff[0] as char);

    std::io::stdout().flush().unwrap();
}

/// Prompt character input
fn trap_in(reg: &mut RegisterStore) {
    print!("Enter a character: ");
    let c = get_char();

    reg[Register::RR0 as usize] = c as u16;

    update_flags(Register::RR0 as u16, reg)
}

/// Output a string
// TODO: Find a safe way to do this
unsafe fn trap_putsp(reg: &mut RegisterStore) {
    // Get pointer to memory offset by Register R0
    let mut c: *mut u16 = &mut (MEMORY.len() as u16 + reg[Register::RR0 as usize]);

    // Loop through memory until the string is terminated
    while *c != 0 {
        let chars = (*c).to_le_bytes();
        print!("{}", chars[0] as char);

        if chars[1] != 0 {
            print!("{}", chars[1] as char);
        }

        // Increment the pointer
        c = c.offset(1);
    }
    std::io::stdout().flush().unwrap();
}

// Halt the program
fn trap_halt(running: &mut bool) {
    *running = false;
}

// Get char from stdin
fn get_char() -> char {
    let mut stdin_handle = stdin().lock();
    let mut byte = [0_u8];
    stdin_handle.read_exact(&mut byte).unwrap();
    std::io::stdout().flush().unwrap();
    return byte[0] as char;
}

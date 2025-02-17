#ifndef AETHER_IR_H
#define AETHER_IR_H

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    IR_NOP,
    IR_MOV,        
    IR_ADD,        
    IR_SUB,        
    IR_AND,        
    IR_ORR,        
    IR_EOR,        
    IR_LSL,        
    IR_LSR,        
    IR_ASR,        
    IR_MUL,        
    IR_NEG,        
    IR_NOT,        
    IR_LOAD,       
    IR_STORE,      
    IR_CMP,        
    IR_BR,         
    IR_RAW,        
} ir_op_t;

typedef struct {
    ir_op_t op;
    uint8_t dst;          
    uint8_t src1;         
    uint8_t src2;         
    int64_t imm;          
    bool is_64bit;
    bool sets_flags;
    uint32_t raw;         
    uint8_t raw_bytes[15]; 
    uint8_t raw_len;       
} ir_inst_t;


bool ir_lift(const uint8_t *code, ir_inst_t *out);

/* Apply semantic-preserving transforms to an IR sequence.
 * Returns number of transforms applied. */
int ir_transform(ir_inst_t *ir, int n, uint32_t rand_seed);

/* Lower one IR instruction back to ARM64. Returns count of ARM64 words emitted (1-3).
 * out[] must have room for 3 words. */
int ir_lower(const ir_inst_t *ir, uint32_t *out);


#include "x86.h"
bool ir_lift_x86(const x86_inst_t *inst, ir_inst_t *out);
int ir_lower_x86(const ir_inst_t *ir, uint8_t *out);

#endif

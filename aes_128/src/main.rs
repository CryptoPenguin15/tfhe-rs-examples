// see https://homes.esat.kuleuven.be/~nsmart/MPC/
// Basic Circuit File 'aes_128.txt'

// dependencies
// tfhe = { version = "*", features = ["boolean", "shortint", "aarch64-unix"] }
// aes="0.8.2"
// bit-vec="0.6.3"

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use bit_vec::BitVec;
use std::fs;
use std::time::Instant;
use std::vec::Vec;
use tfhe::boolean::prelude::*;

fn main() {
    let key = [1u8; 16];
    let block = [2u8; 16];

    let mut ga_block = GenericArray::from(block);
    let cipher = Aes128::new(&GenericArray::from(key));
    cipher.encrypt_block(&mut ga_block);
    println!("ref AES-ECB         {:x}", ga_block);
    let ga_enc_block = GenericArray::from(ga_block);

    cipher.decrypt_block(&mut ga_block);
    assert_eq!(ga_block, GenericArray::from(block));

    let start = Instant::now();
    let algorithm = fs::read_to_string("./aes_128.txt").expect("File not found!");
    println!("file bc read time   {:.2?}", start.elapsed());
    let start = Instant::now();
    let mut instr = Vec::new();
    for (i, line) in algorithm.lines().enumerate() {
        if i <= 2 {
            continue;
        };

        let mut row = Vec::new();
        let mut tokens = line.split(' ').collect::<Vec<_>>();
        if tokens.len() <= 2 {
            continue;
        };
        tokens.remove(0);
        tokens.remove(0);

        for i in tokens.iter().take(tokens.len() - 1) {
            let mut ct = String::from("ct_");
            ct.push_str(i);
            row.push(ct.to_owned());
        }
        let op = tokens[tokens.len() - 1];
        let value = match op {
            "AND" => "bitand\n",
            "INV" => "not\n",
            "XOR" => "bitxor\n",
            &_ => todo!(),
        };
        row.push(value.to_owned());
        instr.push(row.join(" "));
    }
    let alg = instr.join("");

    let mut inp = "".to_string();
    let bv = BitVec::from_bytes(&key);
    for (i, bit) in bv.iter().rev().enumerate() {
        inp = inp.to_owned() + "ct_" + &i.to_string() + " " + &bit.to_string() + "\n";
    }
    let bv = BitVec::from_bytes(&block);
    for (i, bit) in bv.iter().rev().enumerate() {
        inp = inp.to_owned() + "ct_" + &(i + 128).to_string() + " " + &bit.to_string() + "\n";
    }

    let mut out = "".to_string();
    for i in 0..128 {
        out = out.to_owned() + "ct_" + &(36919 - 1 - i).to_string() + " out\n";
    }

    let bc = inp + &alg + &out;
    println!("gen instr time      {:.2?}", start.elapsed());

    let start = Instant::now();
    let (client_key, server_key) = gen_keys();
    println!("gen keys time       {:.2?}", start.elapsed());

    let mut bv = BitVec::new();
    let mut var = std::collections::HashMap::new();
    let op_count = bc.lines().count();
    // op parser credits sarah-ek 
    for (i, line) in bc.lines().enumerate() {
        print!("\rat step {i} out of {op_count}");
        let tokens = line.split(' ').collect::<Vec<_>>();

        let name = tokens[tokens.len() - 2];
        let op = tokens[tokens.len() - 1];
        if op == "out" {
            bv.push(client_key.decrypt(&var[tokens[0]]));
        } else {
            let value = match op {
                "true" => client_key.encrypt(true),
                "false" => client_key.encrypt(false),
                "bitxor" => server_key.xor(&var[tokens[0]], &var[tokens[1]]),
                "bitand" => server_key.and(&var[tokens[0]], &var[tokens[1]]),
                "not" => server_key.not(&var[tokens[0]]),
                s => var[s].clone(),
            };
            var.insert(name, value);
        };
    }
    println!("\ncircuit time        {:.2?}", start.elapsed());

    let b: [u8; 16] = bv.to_bytes().try_into().unwrap();
    let bc_block = GenericArray::from(b);
    println!("cloud AES           {:x}", bc_block);
    assert_eq!(ga_enc_block, bc_block);
}

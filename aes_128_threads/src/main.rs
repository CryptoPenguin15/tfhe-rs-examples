// see https://homes.esat.kuleuven.be/~nsmart/MPC/
// Basic Circuit File 'aes_128.txt'

// dependencies
// tfhe = { version = "*", features = ["boolean", "aarch64-unix"] }
// aes="0.8.2"
// bit-vec="0.6.3"
// rayon="1.7"
// num_cpus="1.15.0"

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use bit_vec::BitVec;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::time::Instant;
use std::vec::Vec;
use tfhe::boolean::prelude::*;

use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering::Relaxed;

fn main() {
    let key = [1u8; 16];
    let block = [2u8; 16];

    let mut ga_block = GenericArray::from(block);
    let cipher = Aes128::new(&GenericArray::from(key));
    cipher.encrypt_block(&mut ga_block);
    println!("ref AES-ECB         {:x}", ga_block);
    let ga_enc_block = ga_block;

    cipher.decrypt_block(&mut ga_block);
    assert_eq!(ga_block, GenericArray::from(block));

    println!("CPU:s physical      {:}", num_cpus::get_physical());
    println!("CPU:s logical       {:}", num_cpus::get());

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
            "AND" => "bitand",
            "INV" => "not",
            "XOR" => "bitxor",
            &_ => todo!(),
        };
        row.push(value.to_owned());
        instr.push(row.join(" "));
    }
    println!("parse file time     {:.2?}", start.elapsed());

    let start = Instant::now();
    let (client_key, server_key) = gen_keys();
    println!("gen keys time       {:.2?}", start.elapsed());

    let mut inp = "".to_string();
    let bv = BitVec::from_bytes(&key);
    for (i, bit) in bv.iter().rev().enumerate() {
        inp = inp.to_owned() + "ct_" + &i.to_string() + " " + &bit.to_string() + "\n";
    }
    let bv = BitVec::from_bytes(&block);
    for (i, bit) in bv.iter().rev().enumerate() {
        inp = inp.to_owned() + "ct_" + &(i + 128).to_string() + " " + &bit.to_string() + "\n";
    }

    let start = Instant::now();
    let map = HashMap::<String, Ciphertext>::new();
    let var = Arc::new(Mutex::new(map));
    inp.par_lines().for_each(|line| {
        let tokens = line.split(' ').collect::<Vec<_>>();

        let name = tokens[tokens.len() - 2];
        let op = tokens[tokens.len() - 1];
        let value = match op {
            "true" => client_key.encrypt(true),
            "false" => client_key.encrypt(false),
            &_ => todo!(),
        };
        var.lock().unwrap().insert(String::from(name), value);
    });
    println!("\nclient_key time ||  {:.2?}", start.elapsed());

    let vlen = instr.len();
    let idx = &AtomicI32::new(0);
    let start = Instant::now();

    thread::scope(|s| {
        for _ in 0..num_cpus::get() {
            let server_key_clone = server_key.clone();
            let instr_clone = instr.clone();
            let var_clone = var.clone();

            s.spawn(move || {
                loop {
                    let b = idx.fetch_add(1, Relaxed);
                    if b >= vlen.try_into().unwrap() {
                        break;
                    }
                    print!("\rat step {b} out of {vlen} ");
                    let st = instr_clone.get(b as usize).unwrap();
                    let tokens = st.split(' ').collect::<Vec<_>>();

                    let op = tokens[tokens.len() - 1];
                    let name = tokens[tokens.len() - 2];

                    let value = match op {
                        "bitxor" => {
                            loop {
                                let var2 = var_clone.lock().unwrap();
                                if !(var2.contains_key(tokens[0]) && var2.contains_key(tokens[1])) {
                                    drop(var2);
                                    thread::sleep(Duration::from_micros(100));
                                } else {
                                    break;
                                }
                            }
                            let var2 = var_clone.lock().unwrap();
                            let t0 = &var2[tokens[0]].clone();
                            let t1 = &var2[tokens[1]].clone();
                            drop(var2);
                            server_key_clone.xor(t0, t1)
                        }
                        "bitand" => {
                            loop {
                                let var2 = var_clone.lock().unwrap();
                                if !(var2.contains_key(tokens[0]) && var2.contains_key(tokens[1])) {
                                    drop(var2);
                                    thread::sleep(Duration::from_micros(100));
                                } else {
                                    break;
                                }
                            }
                            let var2 = var_clone.lock().unwrap();
                            let t0 = &var2[tokens[0]].clone();
                            let t1 = &var2[tokens[1]].clone();
                            drop(var2);
                            server_key_clone.and(t0, t1)
                        }
                        "not" => {
                            loop {
                                let var2 = var_clone.lock().unwrap();
                                if !var2.contains_key(tokens[0]) {
                                    drop(var2);
                                    thread::sleep(Duration::from_micros(100));
                                } else {
                                    break;
                                }
                            }
                            let var2 = var_clone.lock().unwrap();
                            let t0 = &var2[tokens[0]].clone();
                            drop(var2);
                            server_key_clone.not(t0)
                        }
                        &_ => todo!(),
                    };
                    let mut var2 = var_clone.lock().unwrap();
                    var2.insert(name.to_string(), value);
                }
            });
        }
    });
    println!("\nbc time  ||         {:.2?}", start.elapsed());

    let start = Instant::now();
    let mut out = "".to_string();
    for i in 0..128 {
        out = out.to_owned() + "ct_" + &(36919 - 1 - i).to_string() + " out\n";
    }
    let mut bv = BitVec::new();
    for (_, line) in out.lines().enumerate() {
        let tokens = line.split(' ').collect::<Vec<_>>();
        bv.push(client_key.decrypt(&var.lock().unwrap()[tokens[0]]));
    }
    println!("out time            {:.2?}", start.elapsed());

    let b: [u8; 16] = bv.to_bytes().try_into().unwrap();
    let bc_block = GenericArray::from(b);
    println!("cloud AES           {:x}", bc_block);
    assert_eq!(ga_enc_block, bc_block);
}

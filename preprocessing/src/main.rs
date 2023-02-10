use std::fs::File;
//use std::io::Read;
use std::io::prelude::*;
use std::io::{BufRead, BufReader};


fn pad_message(message: &[u8]) -> Vec<u8> {
    let original_len = message.len();
    let mut padded = message.to_vec();

    // Step 1: append a '1' bit
    padded.push(0x80);

    // Step 2: append 0 bits until the length of the padded message is congruent to 448 (mod 512)
    while (padded.len() * 8) % 512 != 448 {
        padded.push(0);
    }

    // Step 3: append the original length of the message as a 64-bit big-endian integer
    let len_bits = (original_len * 8) as u64;
    let len_bytes = len_bits.to_be_bytes();
    padded.extend_from_slice(&len_bytes[..]);

    padded
}

/* 
fn read_file(filename: &str) -> Result<String, std::io::Error> {
    let mut file = File::open(filename)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}
*/




fn main() {


    let file = File::open("file.csv").unwrap();
    let reader = BufReader::new(file);
    let mut prep_file = File::create("pre_file.txt").unwrap();

    for line in reader.lines() {
        // Read line and take the commas out
        let line = line.unwrap();
        let let_without_comma = line.replace(",", "");
        let entry = let_without_comma.as_bytes();

        // preprocess the message
        let padded_message = pad_message(entry);
        //println!("Padded message: {:?}", padded_message);

        // Print the binary representation to prep_file.txt
        //let binary_representation = padded_message.iter().map(|&x| format!("{:08b}", x)).collect::<Vec<String>>().join(" ");
        let binary_representation = padded_message.iter().map(|&x| format!("{}", x)).collect::<Vec<String>>().join(" ");
        //println!("binary representation: {}", binary_representation);
        prep_file.write_all(binary_representation.as_bytes()).unwrap();
        prep_file.write_all(b"\n").unwrap();

    }


}

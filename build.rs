use std::{fs::File, io::Write, path::Path};

fn build_lut<const ALIGNMENT: usize>(
    output: &mut impl Write,
    max_nonce_by_alignment: usize,
) -> std::io::Result<()> {
    let is_be = match std::env::var("CARGO_CFG_TARGET_ENDIAN") {
        Ok(ref s) if s == "big" => true,
        Ok(ref s) if s == "little" => false,
        Ok(e) => panic!(" unknown endianness: {}", e),
        Err(e) => panic!(" unknown endianness: {}", e),
    };
    for i in 0..max_nonce_by_alignment as usize {
        let mut digits = [0; 8];

        let mut word_2s = [0; ALIGNMENT];
        let mut word_3s = [0; ALIGNMENT];
        let mut msg_lens = [0; ALIGNMENT];
        for di in 0..ALIGNMENT {
            let mut copy = i as u64 * ALIGNMENT as u64 + di as u64;
            let mut j = 8;
            loop {
                j -= 1;
                digits[j] = (copy % 10) as u8 + b'0';
                copy /= 10;
                if copy == 0 {
                    break;
                } else if j == 0 {
                    panic!("nonce too large");
                }
            }
            let itoa_buf = &digits[j..];
            let mut output_bytes = [0; 2 * 4];
            output_bytes[..itoa_buf.len()].copy_from_slice(itoa_buf);
            if itoa_buf.len() != 8 {
                output_bytes[itoa_buf.len()] = 0x80;
            } else {
                todo!(">10 million difficulty not supported yet");
            }
            let msg_len = (itoa_buf.len() as u32 + 16) * 8;
            msg_lens[di] = msg_len;
            word_2s[di] = u32::from_be_bytes([
                output_bytes[0],
                output_bytes[1],
                output_bytes[2],
                output_bytes[3],
            ]);
            word_3s[di] = u32::from_be_bytes([
                output_bytes[4],
                output_bytes[5],
                output_bytes[6],
                output_bytes[7],
            ]);
        }
        if is_be {
            word_2s
                .iter_mut()
                .chain(word_3s.iter_mut())
                .chain(msg_lens.iter_mut())
                .for_each(|w| *w = w.swap_bytes());
        }

        for w in word_2s.iter().chain(word_3s.iter()).chain(msg_lens.iter()) {
            output.write_all(&w.to_le_bytes())?;
        }
    }
    Ok(())
}

fn main() -> std::io::Result<()> {
    if std::env::var("CARGO_CFG_TARGET_FEATURE")
        .unwrap()
        .contains("avx512f")
    {
        let out_dir = std::env::var("OUT_DIR").unwrap();
        let out_path = Path::new(&out_dir).join("gts_lut_16.bin");
        let len_path = Path::new(&out_dir).join("gts_lut_16.len");
        let mut output = File::create(out_path)?;

        build_lut::<16>(&mut output, 1_000_000 / 16)?;
        let mut len_output = File::create(len_path)?;
        writeln!(
            len_output,
            "const BUILT_IN_LUT_16_LEN: usize = {} / 16;",
            1_000_000
        )?;
    }
    Ok(())
}

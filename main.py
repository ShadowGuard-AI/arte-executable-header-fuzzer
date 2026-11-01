#!/usr/bin/env python3

import argparse
import logging
import math
import os
import subprocess
import random
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the tool.
    """
    parser = argparse.ArgumentParser(description="Fuzzes the executable header of a given file to test for parsing vulnerabilities in emulators.")
    parser.add_argument("input_file", help="Path to the input executable file.")
    parser.add_argument("-e", "--emulator", default="qemu-system-x86_64", help="Path to the emulator executable. Defaults to qemu-system-x86_64.")
    parser.add_argument("-o", "--output_dir", default="fuzzed_files", help="Directory to store the fuzzed files. Defaults to fuzzed_files.")
    parser.add_argument("-i", "--iterations", type=int, default=10, help="Number of fuzzing iterations. Defaults to 10.")
    parser.add_argument("-f", "--fuzz_factor", type=float, default=0.01, help="Percentage of bytes to fuzz (0.01 = 1%%). Defaults to 0.01.")
    parser.add_argument("--seed", type=int, help="Seed for the random number generator. If not provided, a random seed is used.")
    return parser

def is_valid_file(file_path):
    """
    Checks if a file exists and is a regular file.
    """
    if not os.path.exists(file_path):
        logging.error(f"Error: File '{file_path}' does not exist.")
        return False
    if not os.path.isfile(file_path):
        logging.error(f"Error: '{file_path}' is not a file.")
        return False
    return True

def is_executable(file_path):
    """
    Checks if a file is executable.  Minimal check, may not be foolproof.
    """
    try:
        with open(file_path, 'rb') as f:
            header = f.read(4)
        if header.startswith(b'\x7fELF'):
            return True
        elif header.startswith(b'MZ'):
            return True
        elif header.startswith(b'\xCA\xFE\xBA\xBE') or header.startswith(b'\xFE\xED\xFA\xCE'):  # Mach-O magic numbers
            return True
        else:
            logging.warning(f"Warning: '{file_path}' does not seem to be a recognized executable format (ELF, PE, Mach-O). Proceeding anyway, but results may be unreliable.")
            return True  # Assuming it's an executable and proceeding. User's responsibility.
    except Exception as e:
        logging.error(f"Error checking executable status: {e}")
        return False #Assume not executable

def fuzz_header(input_file, output_file, fuzz_factor, seed=None):
    """
    Fuzzes the header of the input file and saves the fuzzed file.
    Uses bit-flipping and random byte injection based on the fuzz_factor.
    """
    try:
        with open(input_file, "rb") as f:
            original_data = bytearray(f.read())

        file_size = len(original_data)
        # Round up with a minimum of one byte whenever the factor is above
        # zero. int(file size * factor) rounds to zero for small files at
        # small factors (any file under 100 bytes at the default 0.01),
        # which saved byte identical copies while reporting success.
        if fuzz_factor > 0 and file_size > 0:
            num_bytes_to_fuzz = max(1, math.ceil(file_size * fuzz_factor))
        else:
            num_bytes_to_fuzz = 0

        if seed is not None:
            # The caller passes seed + iteration number. Seeding with the
            # same value on every call replays the same random sequence,
            # so every fuzzed file in a run came out byte identical.
            random.seed(seed)

        for _ in range(num_bytes_to_fuzz):
            # The index ranges over the whole file, not the header this
            # tool is named for. On a large binary nearly every mutation
            # lands in the body, so what runs is a whole file mutator
            # whose header hits are a small fraction of the total. The
            # count is also a count of attempts: the same index can be
            # drawn twice, and the second draw can flip a bit back.
            index = random.randint(0, file_size - 1)
            # Choose a random operation: bit flip or random byte injection
            operation = random.choice(["bit_flip", "random_byte"])

            if operation == "bit_flip":
                bit_index = random.randint(0, 7)
                original_data[index] ^= (1 << bit_index)  # Flip the bit
            elif operation == "random_byte":
                original_data[index] = random.randint(0, 255)  # Inject a random byte

        with open(output_file, "wb") as f:
            f.write(original_data)

        logging.info(f"Fuzzed file saved to: {output_file}")

    except Exception as e:
        logging.error(f"Error fuzzing file: {e}")
        return False

    return True


def run_emulator(emulator_path, file_path):
    """
    Runs the emulator with the given file and returns the exit code and output.
    """
    try:
        result = subprocess.run([emulator_path, file_path], capture_output=True, timeout=30)
        return result.returncode, result.stdout.decode('utf-8', errors='ignore'), result.stderr.decode('utf-8', errors='ignore')
    except subprocess.TimeoutExpired:
        logging.warning(f"Emulator timed out after 30 seconds.")
        return -1, "", "Timeout" # Return -1 for timeout

    except FileNotFoundError:
        logging.error(f"Emulator not found at path: {emulator_path}")
        # Timeout, not found, and the generic failure below all return
        # the same minus one, so main's non-zero check cannot tell a
        # hang from a launch error; both read as possible crash in its
        # warning. The stderr string is the only place they differ.
        return -1, "", "Emulator not found"
    except Exception as e:
        logging.error(f"Error running emulator: {e}")
        return -1, "", str(e)

def main():
    """
    Main function to orchestrate the fuzzing process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Input validation
    if not is_valid_file(args.input_file):
        sys.exit(1)

    if not is_executable(args.input_file):
        logging.warning("Input file might not be a valid executable. Continuing with caution.")

    # The default emulator value is a bare program name, not a path, so an
    # os.path.exists check on it fails even when the program is installed
    # and on PATH. Names without a separator go through shutil.which.
    import shutil
    if os.sep in args.emulator:
        emulator_ok = os.path.exists(args.emulator)
    else:
        emulator_ok = shutil.which(args.emulator) is not None
    if not emulator_ok:
        logging.error(f"Emulator not found: {args.emulator}")
        sys.exit(1)

    if args.iterations < 1:
        logging.error("Iterations must be at least 1.")
        sys.exit(1)
    if not 0 < args.fuzz_factor <= 1:
        logging.error("Fuzz factor must be greater than 0 and at most 1.")
        sys.exit(1)

    try:
        os.makedirs(args.output_dir, exist_ok=True)  # Create output directory if it doesn't exist
    except OSError as e:
        logging.error(f"Error creating output directory: {e}")
        sys.exit(1)
    
    if args.seed is None:
        seed = random.randint(0, 2**32 - 1) #generate a random seed
        logging.info(f"Using randomly generated seed: {seed}")
    else:
        seed = args.seed
        logging.info(f"Using provided seed: {seed}")


    for i in range(args.iterations):
        output_file = os.path.join(args.output_dir, f"fuzzed_{i}.bin")
        logging.info(f"Fuzzing iteration: {i + 1}/{args.iterations}")

        if not fuzz_header(args.input_file, output_file, args.fuzz_factor, seed=seed + i):
            logging.error(f"Fuzzing iteration {i+1} failed.")
            continue

        logging.info(f"Running emulator with fuzzed file: {output_file}")
        # The fuzzed file is passed as a bare argument, with no flags
        # telling the emulator what to do with it. For qemu-system that
        # means it is treated as a disk image, and a non-zero exit can
        # be the emulator objecting to its arguments rather than the
        # fuzzed header doing anything. Nothing is saved per crash
        # beyond the fuzzed file itself and these log lines.
        return_code, stdout, stderr = run_emulator(args.emulator, output_file)

        logging.info(f"Emulator finished with return code: {return_code}")
        logging.info(f"Emulator stdout:\n{stdout}")
        logging.info(f"Emulator stderr:\n{stderr}")

        if return_code != 0:
            logging.warning(f"Emulator returned a non-zero exit code for iteration {i+1}. Possible crash or unexpected behavior.")

    logging.info("Fuzzing complete.")

if __name__ == "__main__":
    main()
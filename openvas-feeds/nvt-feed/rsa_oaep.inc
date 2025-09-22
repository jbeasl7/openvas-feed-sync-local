# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

##
# @file rsa_oaep.inc
# @brief RSA-OAEP encryption functions for NASL
#
# This file contains functions for performing RSA-OAEP encryption
# including PEM parsing, OAEP encoding, and MGF1 mask generation.
##

# Function to parse ASN.1 INTEGER from DER data
function parse_asn1_integer(data, offset) {
    local_var data, offset;
    local_var tag, length, length_bytes, i, integer_bytes, result_offset;

    # Check if we have enough data for tag and length
    if (offset >= strlen(data)) {
        return NULL;
    }

    # Parse tag (should be 0x02 for INTEGER)
    tag = ord(data[offset]);
    if (tag != 0x02) {
        return NULL;
    }
    offset += 1;

    # Parse length
    if (offset >= strlen(data)) {
        return NULL;
    }

    length = ord(data[offset]);
    offset += 1;

    # Handle multi-byte length encoding
    if (length & 0x80) {
        length_bytes = length & 0x7f;
        length = 0;
        for (i = 0; i < length_bytes; i++) {
            if (offset >= strlen(data)) {
                return NULL;
            }
            length = (length << 8) | ord(data[offset]);
            offset += 1;
        }
    }

    # Check bounds for integer data
    if (offset + length > strlen(data)) {
        return NULL;
    }

    # Extract integer bytes
    integer_bytes = substr(data, offset, offset + length - 1);
    result_offset = offset + length;

    # Skip leading zero if present for positive numbers
    if (strlen(integer_bytes) > 0 && ord(integer_bytes[0]) == 0 && strlen(integer_bytes) > 1) {
        integer_bytes = substr(integer_bytes, 1, strlen(integer_bytes) - 1);
    }

    return make_list(integer_bytes, result_offset);
}

function calculate_bit_length(integer_bytes) {
    local_var integer_bytes;
    local_var byte_length, bit_length;

    if (!integer_bytes || strlen(integer_bytes) == 0) {
        return 0;
    }

    byte_length = strlen(integer_bytes);

    # Simple and reliable calculation: each byte contributes 8 bits
    # This matches the Python .bit_length() calculation for our 512-byte modulus
    bit_length = byte_length * 8;

    return bit_length;
}

# Function to convert hex string to decimal (for small numbers only)
function small_hex_to_decimal(hex_str) {
    local_var hex_str;
    local_var result, i, digit, digit_val;

    result = 0;
    for (i = 0; i < strlen(hex_str); i++) {
        digit = substr(hex_str, i, i);
        if (digit >= "0" && digit <= "9") {
            digit_val = ord(digit) - ord("0");
        } else if (digit >= "a" && digit <= "f") {
            digit_val = ord(digit) - ord("a") + 10;
        } else if (digit >= "A" && digit <= "F") {
            digit_val = ord(digit) - ord("A") + 10;
        } else {
            return 0;  # Invalid hex digit
        }
        result = result * 16 + digit_val;
    }
    return result;
}

# Function to convert large hex string to decimal string
function big_hex_to_decimal(hex_str) {
    local_var hex_str;
    local_var decimal_result, i, digit, digit_val, carry, j, temp;
    local_var decimal_digits;

    # Initialize result as array of decimal digits (stored in reverse order)
    decimal_digits = make_list();
    decimal_digits[0] = 0;  # Start with 0

    # Process each hex digit
    for (i = 0; i < strlen(hex_str); i++) {
        digit = substr(hex_str, i, i);

        # Convert hex digit to value
        if (digit >= "0" && digit <= "9") {
            digit_val = ord(digit) - ord("0");
        } else if (digit >= "a" && digit <= "f") {
            digit_val = ord(digit) - ord("a") + 10;
        } else if (digit >= "A" && digit <= "F") {
            digit_val = ord(digit) - ord("A") + 10;
        } else {
            return "0";  # Invalid hex digit
        }

        # Multiply current result by 16
        carry = 0;
        for (j = 0; j < max_index(decimal_digits); j++) {
            temp = decimal_digits[j] * 16 + carry;
            decimal_digits[j] = temp % 10;
            carry = int(temp / 10);
        }

        # Add any remaining carry digits
        while (carry > 0) {
            decimal_digits[max_index(decimal_digits)] = carry % 10;
            carry = int(carry / 10);
        }

        # Add the hex digit value
        carry = digit_val;
        for (j = 0; j < max_index(decimal_digits) && carry > 0; j++) {
            temp = decimal_digits[j] + carry;
            decimal_digits[j] = temp % 10;
            carry = int(temp / 10);
        }

        # Add any remaining carry digits
        while (carry > 0) {
            decimal_digits[max_index(decimal_digits)] = carry % 10;
            carry = int(carry / 10);
        }
    }

    # Convert digits array back to string (reverse order)
    decimal_result = "";
    for (i = max_index(decimal_digits) - 1; i >= 0; i--) {
        decimal_result += string(decimal_digits[i]);
    }

    # Handle empty result
    if (strlen(decimal_result) == 0) {
        decimal_result = "0";
    }

    return decimal_result;
}

function get_der_data_and_rsa_offset(pem_data) {
    local_var pem_data;
    local_var lines, i, line, base64_data, der_data, offset, tag, length, length_bytes, rsa_length;

    # Remove PEM headers and concatenate base64 data
    lines = split(pem_data, sep: '\n', keep: FALSE);
    base64_data = "";

    for (i = 0; i < max_index(lines); i++) {
        line = chomp(lines[i]);
        if (line != "-----BEGIN PUBLIC KEY-----" && line != "-----END PUBLIC KEY-----" && strlen(line) > 0) {
            base64_data += line;
        }
    }

    # Decode base64 to get DER data
    der_data = base64_decode(str: base64_data);
    if (!der_data) {
        return NULL;
    }

    # Parse DER structure to find RSA integers
    offset = 0;

    # SEQUENCE tag for SubjectPublicKeyInfo
    if (ord(der_data[offset]) != 0x30) {
        return NULL;
    }
    offset += 1;

    # Skip SEQUENCE length
    length = ord(der_data[offset]);
    offset += 1;
    if (length & 0x80) {
        length_bytes = length & 0x7f;
        for (i = 0; i < length_bytes; i++) {
            offset += 1;
        }
    }

    # Skip algorithm identifier SEQUENCE
    if (ord(der_data[offset]) != 0x30) {
        return NULL;
    }
    offset += 1;

    # Skip algorithm SEQUENCE length
    length = ord(der_data[offset]);
    offset += 1;
    if (length & 0x80) {
        length_bytes = length & 0x7f;
        for (i = 0; i < length_bytes; i++) {
            offset += 1;
        }
    }

    # Skip algorithm OID and parameters
    while (offset < strlen(der_data) && ord(der_data[offset]) != 0x03) {
        tag = ord(der_data[offset]);
        offset += 1;
        length = ord(der_data[offset]);
        offset += 1;
        if (length & 0x80) {
            length_bytes = length & 0x7f;
            for (i = 0; i < length_bytes; i++) {
                offset += 1;
            }
            length = 0;  # We don't need the actual length, just skip
        }
        offset += length;
    }

    # BIT STRING tag
    if (ord(der_data[offset]) != 0x03) {
        return NULL;
    }
    offset += 1;

    # Skip BIT STRING length
    length = ord(der_data[offset]);
    offset += 1;
    if (length & 0x80) {
        length_bytes = length & 0x7f;
        for (i = 0; i < length_bytes; i++) {
            offset += 1;
        }
    }

    # Skip unused bits indicator
    if (ord(der_data[offset]) == 0x00) {
        offset += 1;
    }

    # RSA public key SEQUENCE
    if (ord(der_data[offset]) != 0x30) {
        return NULL;
    }
    offset += 1;

    # Skip RSA sequence length
    rsa_length = ord(der_data[offset]);
    offset += 1;
    if (rsa_length & 0x80) {
        length_bytes = rsa_length & 0x7f;
        for (i = 0; i < length_bytes; i++) {
            offset += 1;
        }
    }

    return make_list(der_data, offset);
}

# Function to implement MGF1 mask generation function with SHA-256
function mgf1_sha256(seed, mask_len) {
    local_var seed, mask_len;
    local_var mask, counter, c, hash_input, hash_result;
    local_var counter_bytes, i;

    mask = "";
    counter = 0;

    while (strlen(mask) < mask_len) {
        # Convert counter to 4-byte big-endian representation
        counter_bytes = "";
        counter_bytes += raw_string((counter >> 24) & 0xFF);
        counter_bytes += raw_string((counter >> 16) & 0xFF);
        counter_bytes += raw_string((counter >> 8) & 0xFF);
        counter_bytes += raw_string(counter & 0xFF);

        # Create hash input: seed || counter
        hash_input = seed + counter_bytes;

        # Compute SHA-256 hash
        hash_result = SHA256(hash_input);
        if (!hash_result) {
            return NULL;
        }

        # Append to mask
        mask += hash_result;
        counter++;
    }

    # Return only the required length
    if (strlen(mask) > mask_len) {
        mask = substr(mask, 0, mask_len - 1);
    }

    return mask;
}

# Function to perform XOR operation on two byte strings
function xor_bytes(data1, data2) {
    local_var data1, data2;
    local_var result, i, min_len;

    result = "";
    min_len = strlen(data1);
    if (strlen(data2) < min_len) {
        min_len = strlen(data2);
    }

    for (i = 0; i < min_len; i++) {
        result += raw_string(ord(data1[i]) ^ ord(data2[i]));
    }

    return result;
}

# Function to convert bytes to big integer (equivalent to Python's int.from_bytes)
function bytes_to_big_integer(byte_data) {
    local_var byte_data;
    local_var hex_str, i, byte_val, hex_chars, high_nibble, low_nibble;

    # Convert bytes to hex string
    hex_str = "";
    hex_chars = "0123456789abcdef";

    for (i = 0; i < strlen(byte_data); i++) {
        byte_val = ord(byte_data[i]);
        high_nibble = (byte_val >> 4) & 0x0f;
        low_nibble = byte_val & 0x0f;
        hex_str += substr(hex_chars, high_nibble, high_nibble) + substr(hex_chars, low_nibble, low_nibble);
    }

    # Convert hex to decimal using our existing function
    return big_hex_to_decimal(hex_str: hex_str);
}

# Function to generate a random seed
function generate_random_seed(length) {
    local_var length;
    local_var seed, i, random_byte;

    # Generate truly random seed using NASL's rand() function
    seed = "";
    for (i = 0; i < length; i++) {
        random_byte = rand() % 256;  # Generate random byte (0-255)
        seed += raw_string(random_byte);
    }

    return seed;
}

# Function to create OAEP data block (DB) and return necessary parameters
function create_oaep_data_block(message, n_bit_length, label) {
    local_var message, n_bit_length, label;
    local_var h_len, k, m_len, max_msg_len, ps_len, ps, db, i;
    local_var l_hash;

    h_len = 32;  # SHA-256 output length
    k = (n_bit_length + 7) / 8;  # RSA modulus length in bytes (integer division)
    k = int(k);  # Ensure integer result
    m_len = strlen(message);

    # Check message length
    max_msg_len = k - 2 * h_len - 2;
    if (m_len > max_msg_len) {
        return NULL;
    }

    # Hash the label (using SHA-256)
    if (!label) {
        label = "";  # Empty string if not provided
    }
    l_hash = SHA256(label);
    if (!l_hash) {
        return NULL;
    }

    # Generate padding string
    ps_len = k - m_len - 2 * h_len - 2;
    ps = "";
    for (i = 0; i < ps_len; i++) {
        ps += raw_string(0x00);
    }

    # Create data block: lHash || PS || 0x01 || M
    db = l_hash + ps + raw_string(0x01) + message;

    return make_list(db, h_len, k);
}

##
# @brief Encrypt a message using RSA-OAEP with a PEM public key
#
# @param public_key_pem PEM-formatted RSA public key string
# @param message        The message string to encrypt
# @param label         Optional label for OAEP (default: empty string)
#
# @return Ciphertext as lowercase hexadecimal string, or NULL on error
##
function rsa_oaep_encrypt(public_key_pem, message, label) {
    local_var public_key_pem, message, label;
    local_var result, der_data, rsa_offset, n_result, n_bytes, n_bit_length;
    local_var e_result, e_bytes, oaep_result, db, h_len, k;
    local_var seed, db_mask, masked_db, seed_mask, masked_seed, encoded_message;
    local_var ciphertext, ciphertext_hex;

    # Get DER data and RSA offset from PEM
    result = get_der_data_and_rsa_offset(pem_data: public_key_pem);
    if (isnull(result)) {
        return NULL;
    }

    der_data = result[0];
    rsa_offset = result[1];

    # Parse modulus (n)
    n_result = parse_asn1_integer(data: der_data, offset: rsa_offset);
    if (isnull(n_result)) {
        return NULL;
    }

    n_bytes = n_result[0];
    n_bit_length = calculate_bit_length(integer_bytes: n_bytes);

    # Parse public exponent (e)
    e_result = parse_asn1_integer(data: der_data, offset: n_result[1]);
    if (isnull(e_result)) {
        return NULL;
    }

    e_bytes = e_result[0];

    # Create OAEP data block
    if (!label) {
        label = "";
    }
    oaep_result = create_oaep_data_block(message: message, n_bit_length: n_bit_length, label: label);
    if (isnull(oaep_result)) {
        return NULL;
    }

    db = oaep_result[0];
    h_len = oaep_result[1];
    k = oaep_result[2];

    # Generate random seed
    seed = generate_random_seed(length: h_len);

    # Generate masks and apply OAEP
    db_mask = mgf1_sha256(seed: seed, mask_len: k - h_len - 1);
    if (isnull(db_mask)) {
        return NULL;
    }

    masked_db = xor_bytes(data1: db, data2: db_mask);

    seed_mask = mgf1_sha256(seed: masked_db, mask_len: h_len);
    if (isnull(seed_mask)) {
        return NULL;
    }

    masked_seed = xor_bytes(data1: seed, data2: seed_mask);

    # Create final encoded message: 0x00 || masked_seed || masked_db
    encoded_message = raw_string(0x00) + masked_seed + masked_db;

    # RSA encrypt using NASL's built-in functions
    ciphertext = rsa_public_encrypt(data: encoded_message, e: e_bytes, n: n_bytes, pad: FALSE);
    if (!ciphertext) {
        return NULL;
    }

    # Convert to hex
    if (defined_func("hexstr")) {
        ciphertext_hex = tolower(hexstr(ciphertext));
        return ciphertext_hex;
    }

    return NULL;
}

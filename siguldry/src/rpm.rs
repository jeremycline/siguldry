

fn header_size(rpm: Vec<u8>) {
    // Koji's size algorithm:

    // 3 bytes of magic, 1 byte version number, 4 bytes reserved.
    let magic = 8;
    let lead_size = 96;

    // Read two 4-byte integers (network byte order) which are
    // - index_entries: number of index entries
    // - data_length: bytes of data in header

    // then header_size is 8 + (16 * index_entries) + data_length
    
    // the signature header is padded, so header_size = header_size + (8 - (header_size % 8)) % 8
    // finally, add 8 bytes for section header
}

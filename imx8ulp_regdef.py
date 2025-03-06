CONTAINER_OFFSET = {
    'SD':       0x8000,
    'eMMCBoot': 0x0,
    'eMMCUser': 0x8000,
    'FSPINAND': 0xFFFF, # Right behind FCB/DBBT ?
    'FSPINOR':  0x1000
}

# Container Header
CONTAINER_HEADER_OFFSETS = {
    'Version':      0x0,
    'LengthLSB':    0x1,
    'LengthMSB':    0x2,
    'Tag':          0x3,
    'Flags':        0x4,
    'SWVersion':    0x8,
    'FuseVersion':  0xA,
    'NumOfImages':  0xB,
    'SigBlkOffset': 0xC,
    'Reserved':     0xE,
    'ImageArray':   0x10
}

CONTAINER_HEADER_LENGTHS = {
    'Version':      0x1,
    'LengthLSB':    0x1,
    'LengthMSB':    0x1,
    'Tag':          0x1,
    'Flags':        0x4,
    'SWVersion':    0x2,
    'FuseVersion':  0x1,
    'NumOfImages':  0x1,
    'SigBlkOffset': 0x2,
    'Reserved':     0x2,
    'ImageArray':   0x80
}

def decode_container_header_flags(flags):
    flags_list = []
    print(f"flags: {flags}")
    flags = int.from_bytes(flags[::-1])
    srk_set = flags & 0b11
    print(f'srk_set: container: {srk_set}')
    if(srk_set == 0):
        flags_list.append('SRK Set: Container not authenticated')
    elif(srk_set == 1):
        flags_list.append('SRK Set: NXP SRK')
    elif(srk_set == 2):
        flags_list.append('SRK Set: OEM SRK')
    else:
        flags_list.append('Reserved')

    srk_key = flags & 0b110000
    flags_list.append(f'SRK key {srk_key} is being used.')

    srk_revoke = flags & 0b111100000000
    flags_list.append(f'SRK revoke mask: {srk_revoke}')

    return flags_list

def decode_image_array_flags(flags):
    flags_list = []
    flags = int.from_bytes(flags[::-1])
    type_of_image = flags & 0b1111
    if(type_of_image == 3):
        type_of_image = 'Executable'
    elif(type_of_image == 4):
        type_of_image = 'Data'
    elif(type_of_image == 6):
        type_of_image = 'ELE'
    elif(type_of_image == 7):
        type_of_image = 'Provisioning image'
    elif(type_of_image == 8):
        type_of_image = 'DEK validation image'
    else:
        type_of_image = 'reserved'

    flags_list.append(f'Type of image: {type_of_image}')

    core_id = flags & 0b11110000
    
    flags_list.append(f'Core ID: {core_id}')

    hash_type = flags & 0b11100000000
    if(hash_type == 0):
        hash_type = 'SHA256'
    elif(hash_type == 1):
        hash_type = 'SHA384'
    elif(hash_type == 2):
        hash_type = 'SHA512'
    
    flags_list.append(f'Hash type: {hash_type}')

    encrypted = flags & 0b100000000000
    
    flags_list.append(f'Image encryption: {encrypted}')

    return flags_list

# Signature Block
SIGNATURE_BLOCK_OFFSETS = {
    'Version':           0x0,
    'LengthLSB':         0x1,
    'LengthMSB':         0x2,
    'Tag':               0x3,
    'CertificateOffset': 0x4,
    'SRKTableOffset':    0x6,
    'SignatureOffset':   0x8,
    'BlobOffset':        0xA,
    'Reserved':          0xA,
    'SRKTable':          0x10,
    'Signature':         0xF,
    'Certificate':       0xF,
    'Blob':              0xF
}

SIGNATURE_BLOCK_LENGTHS = {
    'Version':           0x0,
    'LengthLSB':         0x1,
    'LengthMSB':         0x1,
    'Tag':               0x1,
    'CertificateOffset': 0x2,
    'SRKTableOffset':    0x2,
    'SignatureOffset':   0x2,
    'BlobOffset':        0x2,
    'Reserved':          0x0,
    'SRKTable':          0xF,
    'Signature':         0xF,
    'Certificate':       0xF,
    'Blob':              0xF
}

# Image Array Entry
IMAGE_ARRAY_ENTRY_OFFSETS = {
    'ImageOffset':   0x0,
    'ImageSize':     0x4,
    'LoadAddress':   0x8,
    'EntryPoint':    0x10,
    'Flags':         0x18,
    'ImageMetaData': 0x1c,
    'Hash':          0x20,
    'IV':            0x60
}

IMAGE_ARRAY_ENTRY_LENGTHS = {
    'ImageOffset':   0x4,
    'ImageSize':     0x4,
    'LoadAddress':   0x8,
    'EntryPoint':    0x8,
    'Flags':         0x4,
    'ImageMetaData': 0x4,
    'Hash':          0x40,
    'IV':            0x20
}

# Signature Header
SIGNATURE_HEADER_OFFSETS = {
    'Version':       0x0,
    'LengthLSB':     0x1,
    'LengthMSB':     0x2,
    'Tag':           0x3,
    'Reserved':      0x4,
    'SignatureData': 0x8
}

SIGNATURE_HEADER_LENGTHS = {
    'Version':       0x1,
    'LengthLSB':     0x1,
    'LengthMSB':     0x1,
    'Tag':           0x1,
    'Reserved':      0x4,
    'SignatureData': 0xF           
}

# SRK Table
SRK_HEADER_OFFSETS = {
    'Tag': 0x0,
    'Length': 0x1,
    'Version': 0x3,
    'SRKRecord1': 0xFF,
    'SRKRecord2': 0xFF,
    'SRKRecord3': 0xFF,
    'SRKRecord4': 0xFF
}

SRK_HEADER_LENGTHS = {
    'Tag': 0x1,
    'Length': 0x2,
    'Version': 0x1,
    'SRKRecord1': 0xFF,
    'SRKRecord2': 0xFF,
    'SRKRecord3': 0xFF,
    'SRKRecord4': 0xFF
}

def decode_srk_table(record):
    record_list = []
    #print(record.hex())
    record = record[::-1]
    #print(record.hex())
    record = int.from_bytes(record[::-1])
    
    # Tag
    tag = record & 0xFF
    #print(tag)
    record_list.append(f'Tag: {tag}')

    # Length of SRK
    len = (0xFFFF >> (1*8)) & record
    record_list.append(f'Length of SRK: {len}')

    version = record & (0xFF >> (3*8))
    record_list.append(f'Version: {version}')

    for i in range(len):

        offset = i*len + 4

        record = record << offset

        # Crypto Algo
        crypto_algo = record & (0xFF << 3)
        if(crypto_algo == 0x21):
            crypto_algo = 'RSA'
        elif(crypto_algo == 0x27):
            crypto_algo = 'ECDSA'
        else:
            crypto_algo = 'error'
        record_list.append(f'Crypto Algorithm ({i}): {crypto_algo}')

        # Hash Algo
        algo = record & (0xFF << 4)
        if(algo == 0x00):
            algo = 'SHA-256'
        elif(algo == 0x01):
            algo = 'SHA-384'
        elif(algo == 0x02):
            algo = 'SHA-512'
        else:
            algo = 'error'
        record_list.append(f'Hash Algorithm ({i}): {algo}')

        # Key Size/Curve
        algo = record & (0xFF << 5)
        if(algo == 0x1):
            algo = 'PRIME256V1'
        elif(algo == 0x2):
            algo = 'SEC384R1'
        elif(algo == 0x3):
            algo = 'SEC512R1'
        elif(algo == 0x5):
            algo = 'RSA2048'
        elif(algo == 0x6):
            algo = 'RSA3072'
        elif(algo == 0x7):
            algo = 'RSA4096'
        else:
            algo = 'error'
        record_list.append(f'Key Size/Curve ({i}): {algo}')

        # SRK Flags
        flags = record & (0xFF << 7)
        if(flags == 0x00):
            flags = 'None'
        elif(flags == 0x8):
            flags = 'CA Flag'
        else:
            flags = 'error'
        record_list.append(f'SRK Flags ({i}): {flags}')

        # Crypto Lenghts
        if(crypto_algo == 'RSA'):
            mod_length = record & (0xFFFF << 8)
            record_list.append(f'RSA: Modulus Length: {mod_length}')
            exp_length = record & (0xFFFF << 10)
            record_list.append(f'RSA: Exponent Length: {exp_length}')
        elif(crypto_algo == 'ECDSA'):
            x_length = record & (0xFFFF << 8)
            record_list.append(f'ECDSA: X length: {x_length}')
            y_length = record & (0xFFFF << 10)
            record_list.append(f'ECDSA: Y length: {y_length}')
        else:
            record_list.append('error')
            record_list.append('error')

        # Need to add decoding for RSA mod/exp or ecdsa x/y

    return record_list


    

# Certificate Header
CERTIFICATE_HEADER_OFFSETS = {
    'Version':             0x0,
    'LengthLSB':           0x1,
    'LengthMSB':           0x2,
    'Tag':                 0x3,
    'SignatureOffset':     0x4,
    'PermissionsInverted': 0x6,
    'Permissions':         0x7,
    'PublicKey':           0x8,
    'Signature':           0xF
}

CERTIFICATE_HEADER_LENGTHS = {
    'Version':             0x1,
    'LengthLSB':           0x1,
    'LengthMSB':           0x1,
    'Tag':                 0x1,
    'SignatureOffset':     0x2,
    'PermissionsInverted': 0x1,
    'Permissions':         0x1,
    'PublicKey':           0xF,
    'Signature':           0xF
}

BLOB_OFFSETS = {
    'Version':    0x0,
    'LengthLSB':  0x1,
    'LengthMSB':  0x2,
    'Tag':        0x3,
    'Flags':      0x4,
    'Size':       0x5,
    'Algorithm':  0x6,
    'Mode':       0x7,
    'WrappedKey': 0x8
}

BLOB_LENGTHS = {
    'Version':    0x1,
    'LengthLSB':  0x1,
    'LengthMSB':  0x1,
    'Tag':        0x1,
    'Flags':      0x1,
    'Size':       0x1,
    'Algorithm':  0x1,
    'Mode':       0x1,
    'WrappedKey': 0xF 
}

IMAGE_ARRAY_ENTRY_LENGTH = 128
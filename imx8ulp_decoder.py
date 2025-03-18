from dataclasses import dataclass
from typing import List, Dict
import struct
import pprint

# Define structured classes for headers and entries
@dataclass
class ContainerHeader:
    version: int
    length: int
    tag: int
    flags: int
    sw_version: int
    fuse_version: int
    num_of_images: int
    sig_blk_offset: int
    reserved: int
    image_array: List[Dict]

    def decode_flags(self):
        flags_list = []
        
        srk_set = self.flags & 0b11
        flags_list.append(["Container not authenticated", "NXP SRK", "OEM SRK", "Reserved"][srk_set])

        srk_key = (self.flags >> 4) & 0b11
        flags_list.append(f"SRK key {srk_key} is being used.")

        srk_revoke = (self.flags >> 8) & 0b1111
        flags_list.append(f"SRK revoke mask: {srk_revoke}")

        self.flags = flags_list

@dataclass
class ImageArrayEntry:
    image_offset: int
    image_size: int
    load_address: int
    entry_point: int
    flags: int
    image_metadata: int
    hash_value: int
    iv: int

    def decode_flags(self):
        flags_list = []

        type_of_image = self.flags & 0b1111
        flags_list.append('Type of image: ' + {3:'Executable', 4:'Data', 6:'ELE', 7:'Provisioning Image', 8:'DEK Validation Image'}[type_of_image])

        core_id = (self.flags >> 4) & 0b1111
        flags_list.append(f'Core ID: {core_id}')

        hash_type = (self.flags >> 8) & 0b111
        hash_type = ['SHA256', 'SHA384', 'SHA512'][hash_type]
        flags_list.append(f'Hash Type: {hash_type}')

        encrypted = (self.flags >> 11) & 0b1
        flags_list.append(f'Encrypted?: {encrypted}')

        self.flags = flags_list
    
@dataclass
class SignatureBlock:
    version: int
    length: int
    tag: int
    certificate_offset: int
    srk_table_offset: int
    signature_offset: int
    blob_offset: int
    reserved: int
    srk_table: List[Dict]
    signature_header: None
    certificate_header: None
    blob: None
    
@dataclass
class SRKTable:
    tag: int
    len: int
    version: int
    srk_table_entries: List[Dict]

@dataclass
class SRKTableEntry:
    tag: int
    length: int
    crypto_algo: int
    hash_algo: int
    key_size: int
    not_used: int
    srk_flags: int
    mod_x_len: int # RSA: Mod, ECDSA: X
    exp_y_len: int # RSA: Exp, ECDSA: Y
    mod_x: int # BIG ENDIAN
    exp_y: int # BIG ENDIAN

    def decode_flags(self):
        self.crypto_algo = {33:'rsa', 39:'ecdsa'}[self.crypto_algo]
        self.hash_algo = ['sha256', 'sha384', 'sha512'][self.hash_algo]
        self.key_size = {1:'prime256v1', 2:'sec384r1', 3:'sec512r1', 4:'rsa2048', 5:'rsa2048', 6:'rsa3072', 7:'rsa4096'}[self.key_size]
        self.srk_flags = {0:'none', 8:'ca flag'}[self.srk_flags]

@dataclass
class SignatureHeader:
    version: int
    length: int
    tag: int
    reserved: int
    signature_data: None

@dataclass
class CertificateHeader:
    version: int
    length: int
    tag: int
    signature_offset: int
    permissions_n: None
    permissions: None
    public_key: int
    signature: int

@dataclass
class Blob:
    version: int
    length: int
    tag: int
    flags: int
    size: int
    algorithm: int
    mode: int
    wrapped_key: int

    def decode_flags(self):
        self.flags = {0x80:'KEK key flag'}[self.flags]
        self.size = {0x10:'128 bit AES key', 0x18:'192 bit AES key', 0x20:'256 bit AES key'}[self.size]
        self.algorithm = {0x55:'AES'}[self.algorithm]
        self.mode = {0x67:'CBC'}[self.mode]

class IMX8ULPBootContainer:
    def __init__(self, filepath):
        self.filepath = filepath
        with open(filepath, "rb") as f:
            self.dump = f.read()
        self.signature_block_offset = None

    def decode_container_header(self, index: int) -> ContainerHeader:
        offset = 0 if index == 0 else 0x400
        dump = self.dump[offset:]
        
        header_values = struct.unpack("<BHBIHBBHH", dump[:16])
        container_header = ContainerHeader(*header_values, image_array=[])
        num_of_images = container_header.num_of_images
        container_header.decode_flags()
        
        # Decode image array entries
        image_entries = []
        #print(num_of_images)
        for i in range(num_of_images):
            entry_offset = 0x10 + i * 128
            entry_values = struct.unpack("<IIQQII64s32s", dump[entry_offset:entry_offset+128])
            image_entries.append(ImageArrayEntry(*entry_values))
            image_entries[i].decode_flags()
            self.hexify(image_entries[i])
        
        container_header.image_array = image_entries
        self.signature_block_offset = container_header.sig_blk_offset

        #print('running hexify')
        self.hexify(container_header)

        return container_header

    def decode_signature_block(self, index: int) -> SignatureBlock:
        # Signature Block
        base_offset = 0 if index == 0 else 0x400
        dump = self.dump[base_offset + self.signature_block_offset:]
        signature_values = struct.unpack("<BHBHHHHI", dump[:16])
        # Signature Block, SRK Table, Signature Header, Certificate Header, Blob
        signature_block = SignatureBlock(*signature_values, None, None, None, None)

        # SRK Table
        offset = signature_block.srk_table_offset
        if(offset != 0):
            srk_table_header = struct.unpack("<BHB", dump[offset:offset+4])
            srk_table = SRKTable(*srk_table_header, srk_table_entries = [])
        
            srk_table_entry_len = ((srk_table.len) / 4) - 1

            for i in range(4):
                start = int(20+(srk_table_entry_len*i))
                end = int(start + srk_table_entry_len - 1)
                #extra = (end-start) - 12
                #print(start)
                #print(end)
                srk_table_entry = struct.unpack("<BHBBBBBHH", dump[start:start+12])
                srk_table_entry = SRKTableEntry(*srk_table_entry, mod_x=None, exp_y=None)
                srk_table_entry.mod_x = dump[start+12:start+12+srk_table_entry.mod_x_len]
                srk_table_entry.exp_y = dump[start+12+srk_table_entry.mod_x_len:start+12+srk_table_entry.mod_x_len+srk_table_entry.exp_y_len]
                srk_table_entry.decode_flags()
                self.hexify(srk_table_entry)
                srk_table.srk_table_entries.append(srk_table_entry)

            signature_block.srk_table = srk_table

        # Signature Header'
        offset = signature_block.signature_offset
        if(offset != 0):
            signature_header = struct.unpack("<BHBI", dump[offset:offset+8])
            signature_block.signature_header = SignatureHeader(*signature_header, None)
            signature_block.signature_header.signature_data = dump[offset+8:offset+signature_block.signature_header.length]
            self.hexify(signature_block.signature_header)

        # Certificate Header
        offset = signature_block.certificate_offset
        if(offset != 0):
            certificate_header = struct.unpack("<BHBH", dump[offset:offset+6])
            signature_block.certificate_header = CertificateHeader(*certificate_header, None, None, None, None)
            # make a variable to make less words..
            cert = signature_block.certificate_header
            cert.public_key = dump[offset+8:offset+cert.signature_offset]
            self.hexify(signature_block.certificate_header)

        # Blob (DEK)
        offset = signature_block.blob_offset
        if(offset != 0):
            blob = struct.unpack("<BHBBBBB", dump[offset:offset+8])
            signature_block.blob = Blob(*blob, None)
            signature_block.blob.decode_flags()
            signature_block.blob.wrapped_key = dump[offset+8:offset+signature_block.blob.length]
            self.hexify(signature_block.blob)

        return signature_block
    
    
    def extract_images(self, container_header: ContainerHeader):
        for i, image in enumerate(container_header.image_array):
            with open(f"image{i}.bin", "wb") as f:
                f.write(self.dump[image.image_offset:image.image_offset + image.image_size])

    def hexify(self, instance):
        for item in instance.__dict__:
            if(type(instance.__dict__[item]) == int):
                instance.__dict__[item] = hex(instance.__dict__[item])
            if(type(instance.__dict__[item]) == bytes):
                instance.__dict__[item] = f'0x{instance.__dict__[item].hex()}'

def main():
    container = IMX8ULPBootContainer("imx-boot-imx8ulp-lpddr4-evk-sd.bin-flash_singleboot_m33")
    container_header = container.decode_container_header(0)
    print('===== FIRST CONTAINER HEADER =====')
    pprint.pp(container_header)
    signature_block = container.decode_signature_block(0)
    print('\n===== FIRST SIGNATURE BLOCK =====')
    pprint.pp(signature_block)
    container_header = container.decode_container_header(1)
    print('\n===== SECOND CONTAINER HEADER =====')
    pprint.pp(container_header)
    signature_block = container.decode_signature_block(1)
    print('\n===== SECOND SIGNATURE BLOCK =====')
    pprint.pp(signature_block)
    #container.extract_images(container_header)


if __name__ == '__main__':
    main()

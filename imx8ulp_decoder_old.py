import pprint
from imx8ulp_regdef import *

"""
Page size of boot device is a parameter that can change offsets of images in this container.
This code only supports SD/eMMC currently, where the page size is 512B.
• The image offset, relative to the ELE container start on the boot device, must be MAX[1KB,
PAGE_SIZE_OF_BOOT_DEVICE] aligned. The only exception is the scenario of a 16KB page size NAND boot, where the
offset of ELE FW can be [8KB, 15KB] with 1KB aligned.
• For the ELE FW, the image size must be 4 bytes aligned. For the images in the 2nd container, the container, they must be
MAX[1KB, PAGE_SIZE_OF_BOOT_DEVICE] aligned.
"""

class imx8ulp_boot_container:

    def __init__(self, filepath):
        self.filepath = filepath
        
        # Open file
        f = open(filepath, "rb")

        # Dump contents
        self.dump = f.read()

        
        # Below code not needed - hardcode it
        """
        for key in self.IMAGE_ARRAY_ENTRY_LENGTHS:
            self.image_array_entry_length = self.image_array_entry_length + self.IMAGE_ARRAY_ENTRY_LENGTHS[key]
        print(self.image_array_entry_length)
        """

    """
	1. Decode Container Header
	2. Decode Image Array using NumOfImages
		a. Store offsets and sizes of binaries in an array
	3. Decode Signature Block using SigBlkOffset
		a. Decode SRKTable
			i. Decode SRK Recordsg
		b. Decode Signature Header
		c. Check to see if Certificate Header exists by reading offset
			i. Decode certificate Header if so
		d. Check to see if Blob (DEK) exists by reading offset
			i. Decode Blob (DEK) if so
    """

    def decode_container_header(self, index):
        # Decode Container Header
        ############################ STEP 1 ############################
        if(index == 0):
            dump = self.dump[0:] # get full dump from 0 offset
        elif(index == 1):
            dump = self.dump[0x400:]
        container_header_values = CONTAINER_HEADER_OFFSETS.copy()
        for key in CONTAINER_HEADER_OFFSETS:
            if(key == 'ImageArray'):
                break
            container_header_values[key] = dump[CONTAINER_HEADER_OFFSETS[key]:CONTAINER_HEADER_OFFSETS[key]
                                                          + CONTAINER_HEADER_LENGTHS[key]] # int.from_bytes()
        ########################### STEP 1 #############################
        
        ########################### STEP 2 #############################
        # Decode Image Array
        num_of_images = container_header_values['NumOfImages'] # Grab number of images EQUALS 1
        image_array_entries = [] # Create empty list of entries
        #image_array_entry_values = IMAGE_ARRAY_ENTRY_OFFSETS # Instantiate a values dict based on offsets like above
        num_of_images = int.from_bytes(num_of_images[::-1])
        image_array_dump = dump[0x10:0x10+(num_of_images*128)] # Grab dump of image array data from container header values
        # THIS IS THE FULL DUMP OF THE WHOLE ARRAY

        # loop through image array entries
        for i in range(num_of_images):
            image_array_entry_values = IMAGE_ARRAY_ENTRY_OFFSETS.copy()
            image_array_entry_offset = i * IMAGE_ARRAY_ENTRY_LENGTH
            #print(f'image_array_entry_offset: {image_array_entry_offset}')
            for key in IMAGE_ARRAY_ENTRY_OFFSETS:
                image_array_entry_values[key] = image_array_dump[IMAGE_ARRAY_ENTRY_OFFSETS[key]+image_array_entry_offset:
                                                                    IMAGE_ARRAY_ENTRY_OFFSETS[key]+image_array_entry_offset + 
                                                                    IMAGE_ARRAY_ENTRY_LENGTHS[key]]
            image_array_entry_values['Flags'] = decode_image_array_flags(image_array_entry_values['Flags'])
            image_array_entries.append(image_array_entry_values)
            #print(f"AFTER: IMAGE_ARRAY_ENTRY_OFFSETS: {IMAGE_ARRAY_ENTRY_OFFSETS}")

        container_header_values['ImageArray'] = image_array_entries

        # Set signature block offset
        self.signature_block_offset = container_header_values['SigBlkOffset']

        # Decode flags
        container_header_values['Flags'] = decode_container_header_flags(container_header_values['Flags'])

        self.dump_image(container_header_values['ImageArray'], num_of_images)
        self.hexify(container_header_values)
        for i in range(len(container_header_values['ImageArray'])):
            self.hexify(container_header_values['ImageArray'][i])
        pprint.pp(container_header_values)

    def decode_signature_block(self, index):
        if(index == 0):
            dump = self.dump[0+int.from_bytes(self.signature_block_offset, "little"):]
        if(index == 1):
            dump = self.dump[0x400+int.from_bytes(self.signature_block_offset, "little"):]
        signature_block_values = SIGNATURE_BLOCK_OFFSETS.copy()
        for key in SIGNATURE_BLOCK_OFFSETS:
            # check to see if certificate or blob exist
            if((key == 'Certificate' and signature_block_values['CertificateOffset'] == b'\x00\x00') or
               (key == 'Blob' and signature_block_values['BlobOffset'] == b'\x00\x00')):
                signature_block_values[key] = b'\x00'
                continue

            # change values
            signature_block_values[key] = dump[SIGNATURE_BLOCK_OFFSETS[key]:SIGNATURE_BLOCK_OFFSETS[key] + SIGNATURE_BLOCK_LENGTHS[key]]
            
            # Set offsets
            if(key == 'CertificateOffset'):
                SIGNATURE_BLOCK_OFFSETS['Certificate'] = int.from_bytes(signature_block_values[key])
            if(key == 'SRKTableOffset'):
                SIGNATURE_BLOCK_OFFSETS['SRKTable'] = int.from_bytes(signature_block_values[key])
            if(key == 'SignatureOffset'):
                SIGNATURE_BLOCK_OFFSETS['SignatureOffset'] = int.from_bytes(signature_block_values[key])
            if(key == 'BlobOffset'):
                SIGNATURE_BLOCK_OFFSETS['BlobOffset'] = int.from_bytes(signature_block_values[key])

        #print(SIGNATURE_BLOCK_OFFSETS)

        #print(signature_block_values['SRKTable'])
        #print(self.hexify(signature_block_values['SRKTable']))
        signature_block_values['SRKTable'] = decode_srk_table(signature_block_values['SRKTable'])    
       
        self.hexify(signature_block_values)
       
        pprint.pp(signature_block_values)

    def hexify(self, dictionary):
        if(type(dictionary) == list):
            return
        for key,value in dictionary.items():
            if isinstance(value, list):
                self.hexify(value)
            else:
                #print(dictionary[key])
                dictionary[key] = f'0x{dictionary[key].hex()}'

    def dump_image(self, image_array, num_of_images):
        for i in range(num_of_images):
            f = open(f'image{i}.bin', 'wb')
            offset = int.from_bytes(image_array[i]['ImageOffset'])
            length = int.from_bytes(image_array[i]['ImageSize'])
            #print(self.dump)
            #print(f'length of dump: {len(self.dump)}')
            #print(offset)
            #print(length)
            #print(self.dump[offset:offset+length])
            f.write(self.dump[offset:offset+length])



container = imx8ulp_boot_container("imx-boot-imx8ulp-lpddr4-evk-sd.bin-flash_singleboot_m33")
print('==========================FIRST BOOT CONTAINER==========================')
container.decode_container_header(0)
container.decode_signature_block(0)
print('==========================SECOND BOOT CONTAINER==========================')
container.decode_container_header(1)
container.decode_signature_block(1)

#print(dump)


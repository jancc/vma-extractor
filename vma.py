#!/usr/bin/env python3
from io import BufferedReader, BufferedWriter, BytesIO
import os
import sys
import hashlib
import argparse


class VmaHeader():
    def __init__(self, fo: BufferedReader, skip_hash: bool):
        b = BytesIO(fo.read(60))
        assert len(b.getbuffer()) == 60

        # 0 -  3:   magic
        #     VMA magic string ("VMA\x00")
        magic = b.read(4)
        assert magic == b'VMA\0'

        # 4 -  7:   version
        #     Version number (valid value is 1)
        version = int.from_bytes(b.read(4), 'big')
        assert version == 1

        # 8 - 23:   uuid
        #     Unique ID, Same uuid is used to mark extents.
        self.uuid = b.read(16)

        # 24 - 31:   ctime
        #     Backup time stamp (seconds since epoch)
        self.ctime = int.from_bytes(b.read(8), 'big')

        # 32 - 47:   md5sum
        #     Header checksum (from byte 0 to header_size). This field
        #     is filled with zero to generate the checksum.
        self.md5sum = b.read(16)

        # 48 - 51:   blob_buffer_offset
        #     Start of blob buffer (multiple of 512)
        self.blob_buffer_offset = int.from_bytes(b.read(4), 'big')

        # 52 - 55:   blob_buffer_size
        #     Size of blob buffer (multiple of 512)
        self.blob_buffer_size = int.from_bytes(b.read(4), 'big')

        # 56 - 59:   header_size
        #     Overall size of this header (multiple of 512)
        self.header_size = int.from_bytes(b.read(4), 'big')
        assert self.header_size % 512 == 0

        # Buffer the rest of the header
        b.write(fo.read(self.header_size - 60))
        b.seek(60, os.SEEK_SET)
        assert len(b.getbuffer()) == self.header_size

        # Calculate the checksum now that we have the full header
        if skip_hash:
            self.generated_md5sum = None
        else:
            h = hashlib.md5()
            data = b.getbuffer()
            h.update(data[:32])
            h.update(b'\0' * 16)    # zero out the md5sum field
            h.update(data[48:])
            self.generated_md5sum = h.digest()

        # 60 - 2043: reserved
        b.read(1984)

        # 2044 - 3067: uint32_t config_names[256]
        #     Offsets into blob_buffer table
        self.config_names: list[int] = []
        for _ in range(256):
            self.config_names.append(int.from_bytes(b.read(4), 'big'))

        # 3068 - 4091: uint32_t config_data[256]
        #     Offsets into blob_buffer table
        self.config_data: list[int] = []
        for _ in range(256):
            self.config_data.append(int.from_bytes(b.read(4), 'big'))

        # 4092 - 4095: reserved
        b.read(4)

        # 4096 - 12287: VmaDeviceInfoHeader dev_info[256]
        #     The offset in this table is used as 'dev_id' inside
        #     the data streams.
        self.dev_info: list[VmaDeviceInfoHeader] = []
        for i in range(256):
            self.dev_info.append(VmaDeviceInfoHeader(b, self))

        # 12288 - header_size: Blob buffer

        # the blob buffer layout is very odd. there appears to be an additional
        # byte of padding at the beginning
        b.read(1)

        # since byte-wise offsets are used to address the blob buffer, the
        # blob metadata is stored in a hashmap, with the offsets as the keys
        self.blob_buffer: dict[int, Blob] = {}
        blob_buffer_current_offset = 1
        while(b.tell() < self.blob_buffer_offset + self.blob_buffer_size):
            self.blob_buffer[blob_buffer_current_offset] = Blob(b)
            blob_buffer_current_offset = b.tell() - self.blob_buffer_offset


class VmaDeviceInfoHeader():
    def __init__(self, b: BytesIO, vma_header: VmaHeader):
        self.__vma_header = vma_header
        self.device_name = int.from_bytes(b.read(4), 'big')     # 0 -  3:   devive name (offsets into blob_buffer table)
        b.read(4)                                               # 4 -  7:   reserved
        self.device_size = int.from_bytes(b.read(8), 'big')     # 8 - 15:   device size in bytes
        b.read(16)                                              # 16 - 31:   reserved

    def get_name(self):
        name = self.__vma_header.blob_buffer[self.device_name].data
        return name.split(b'\0')[0].decode('utf-8')


class VmaExtentHeader():
    def __init__(self, fo: BufferedReader, vma_header: VmaHeader, skip_hash: bool):
        b = BytesIO(fo.read(512))

        l = len(b.getbuffer())
        if l == 0:
            raise EOFError
        assert l == 512, f'Expected 512 bytes, got {l}'

        # 0 -  3:   magic
        #     VMA extent magic string ("VMAE")
        magic = b.read(4)
        assert magic == b'VMAE'

        # 4 -  5:   reserved
        b.read(2)

        # 6 -  7:   block_count
        #     Overall number of contained 4K block
        self.block_count = int.from_bytes(b.read(2), 'big')

        # 8 - 23:   uuid
        #     Unique ID, Same uuid as used in the VMA header.
        self.uuid = b.read(16)

        # 24 - 39:   md5sum
        #     Header checksum (from byte 0 to header_size). This field
        #     is filled with zero to generate the checksum.
        self.md5sum = b.read(16)

        # 40 - 511:   blockinfo[59]
        self.blockinfo: list[Blockinfo] = []
        for i in range(59):
            self.blockinfo.append(Blockinfo(b, vma_header))

        # Calculate checksum
        if skip_hash:
            self.generated_md5sum = None
        else:
            h = hashlib.md5()
            data = b.getbuffer()
            h.update(data[:24])
            h.update(b'\0' * 16)    # zero out the md5sum field
            h.update(data[40:])
            self.generated_md5sum = h.digest()


class Blob():
    def __init__(self, b: BytesIO):
        # the size of a blob is a two-byte int in LITTLE endian
        # source: original c code of vma-reader
        #    uint32_t size = vmar->head_data[bstart] +
        #        (vmar->head_data[bstart+1] << 8);
        self.size = int.from_bytes(b.read(2), 'little')
        self.data = b.read(self.size)


class Blockinfo():
    CLUSTER_SIZE = 65536

    def __init__(self, b: BytesIO, vma_header: VmaHeader):
        self.mask = int.from_bytes(b.read(2), 'big')        # 0 - 1: mask
        b.read(1)                                           # 2:     reserved
        self.dev_id = int.from_bytes(b.read(1), 'big')      # 3:     dev_id - Device ID (offset into dev_info table)
        self.cluster_num = int.from_bytes(b.read(4), 'big') # 4 - 7: cluster_num


def extract_configs(args: argparse.Namespace, vma_header: VmaHeader):
    """
    Configs in VMA are composed of two blobs. One specifies the config's
    filename and the other contains the config's content.
    The filename seems to be a null-terminated string, while the content is not
    terminated.
    """
    if args.verbose: print('extracting configs...')

    for i in range(256):
        if vma_header.config_names[i] == 0:
            continue
        config_name = vma_header.blob_buffer[vma_header.config_names[i]].data
        # interpret filename as a null-terminated utf-8 string
        config_name = config_name.split(b'\0')[0]

        if args.verbose:
            print(f'{config_name.decode()}...', end='')

        config_data = vma_header.blob_buffer[vma_header.config_data[i]].data

        with open(os.path.join(args.destination, config_name.decode()), 'wb') as config_fo:
            config_fo.write(config_data)

        if args.verbose:
            print(' OK')


def extract(fo: BufferedReader, args: argparse.Namespace):
    os.makedirs(args.destination, exist_ok=True)

    vma_header = VmaHeader(fo, args.skip_hash)

    # check the md5 checksum given in the header with the value calculated from
    # the file
    if vma_header.generated_md5sum is not None:
        assert vma_header.md5sum == vma_header.generated_md5sum

    extract_configs(args, vma_header)
    #assert fo.tell() == vma_header.header_size     # Not possible if fo is stdin

    if args.verbose:
        print('extracting devices...')

    # open file handlers for all devices within the VMA
    # so we can easily append data to arbitrary devices
    device_fos: dict[int, BufferedWriter] = {}
    for dev_id, dev_info in enumerate(vma_header.dev_info):
        if dev_info.device_size > 0:
            if args.verbose:
                print(dev_info.get_name())
            p = os.path.join(args.destination, dev_info.get_name())
            # Add .raw if the file doesn't have an extension (like Proxmox `vma` command does)
            if not os.path.splitext(p)[1]:
                p += '.raw'
            device_fos[dev_id] = open(p, 'wb')

    if args.verbose:
        print('this may take a while...')

    # used for sanity checking
    cluster_num_prev = -1

    zeroes_4k = b'\0' * 4096

    while True:
        try:
            # when there is data to read at this point, we can safely expect a full
            # extent header with additional clusters, or EOF
            extent_header = VmaExtentHeader(fo, vma_header, args.skip_hash)
            assert vma_header.uuid == extent_header.uuid
        except EOFError:
            break

        # check the md5 checksum given in the header with the value calculated from
        # the file
        if extent_header.generated_md5sum is not None:
            assert extent_header.md5sum == extent_header.generated_md5sum

        for blockinfo in extent_header.blockinfo:
            if blockinfo.dev_id == 0:
                continue

            device_fo = device_fos[blockinfo.dev_id]
            dev_info = vma_header.dev_info[blockinfo.dev_id]

            cluster_pos = blockinfo.cluster_num * Blockinfo.CLUSTER_SIZE

            # non-sequential clusters encountered, handle this case
            if blockinfo.cluster_num != cluster_num_prev + 1:
                if args.verbose:
                    print('non sequential cluster encountered...')

                device_fo.seek(0, os.SEEK_END)
                written_size = device_fo.tell()

                if written_size < cluster_pos:
                    if args.sparse:
                        # In sparse mode, seek to the cluster position
                        device_fo.seek(cluster_pos, os.SEEK_SET)
                    else:
                        # add padding for missing clusters
                        if args.verbose:
                            print(f'{blockinfo.cluster_num}')
                            print(f'adding {cluster_pos - written_size} bytes of padding...')

                        # write padding in chunks of 4096 bytes to avoid RAM exhaustion
                        padding = cluster_pos - written_size
                        while padding > 0:
                            device_fo.write(zeroes_4k if padding >= 4096 else zeroes_4k[:padding])
                            padding -= 4096

            device_fo.seek(cluster_pos, os.SEEK_SET)
            cluster_num_prev = blockinfo.cluster_num

            for i in range(16):
                # a 2-bytes wide bitmask indicates 4k blocks with only zeros
                block_pos = cluster_pos + i * 4096
                if block_pos >= dev_info.device_size:
                    break  # We've reached the end of the device

                if (1 << i) & blockinfo.mask:
                    device_fo.write(fo.read(4096))
                elif args.sparse:
                    # In sparse mode, seek past the zero block or to the end of the device
                    device_fo.seek(4096, os.SEEK_CUR)
                else:
                    device_fo.write(zeroes_4k)


    if args.verbose:
        print('closing file handles...')

    for i, device_fo in device_fos.items():
        # truncate the file to the correct size
        device_fo.seek(0, os.SEEK_END)
        device_fo.truncate(vma_header.dev_info[i].device_size)
        device_fo.close()


    if args.verbose:
        print('done')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', type=str)
    parser.add_argument('destination', type=str)
    parser.add_argument('-v', '--verbose', default=False, action='store_true')
    parser.add_argument('-f', '--force', default=False, action='store_true',
            help='overwrite target file if it exists')
    parser.add_argument('--skip-hash', default=False, action='store_true',
            help='do not perform md5 checksum test of data')
    parser.add_argument('--sparse', default=False, action='store_true',
            help='write sparse files')
    args = parser.parse_args()

    if(not os.path.exists(args.filename)):
        print('Error! Source file does not exist!')
        return 1

    if(os.path.exists(args.destination) and not args.force):
        print('Error! Destination path exists!')
        return 1

    with open(args.filename, 'rb') as fo:
        extract(fo, args)

    return 0

if __name__ == '__main__':
    sys.exit(main())

import sys

# Use little endian for byte swapped *.bin files
ENDIAN = 'big'

WORDS_PER_FRAME = 101
FRAME_ADDR_CMD = 0x30002001

INIT_COMMANDS = [
        0xffffffff,
        0xffffffff,
        0x000000bb,
        0x11220044,
        0xffffffff,
        0xaa995566,
        0x20000000,

        0x30008001,
        0x00000007,     # RCRC command
        0x20000000,
        0x30018001,
        0x23727093,     # IDCODE value
        0x30008001,
        0x00000001,     # WCFG command
        0x20000000 ]
        # 0x30002001,
        # 0x00000000,
        # 0x30004000 | WORDS_PER_FRAME ] + [0]*WORDS_PER_FRAME    # Dummy frame

# END_COMMANDS = [ 0x30004000 | WORDS_PER_FRAME ] + [0]*WORDS_PER_FRAME + [
END_COMMANDS = [
        0x30008001,
        0x00000007,     # RCRC command
        0x20000000,
        0x30008001,
        0x0000000d ]    # DESYNC command

def extract_frame(f, faddr):
    buf = b''
    while True:
        word = f.read(4)
        if word == b'':
            break
        # Find frame address command
        if int.from_bytes(word, ENDIAN) == FRAME_ADDR_CMD:
            word = f.read(4)
            # Match with the frame address
            if int.from_bytes(word, ENDIAN) == faddr:
                f.seek(-(8 + WORDS_PER_FRAME*4 + 4), 1)
                buf += f.read(4)    # FDRI command
                for i in range(WORDS_PER_FRAME):
                    buf += f.read(4)
                buf += f.read(4)    # FAR command
                buf += f.read(4)    # Frame Address
                f.read(4)           # CRC command
                f.read(4)           # CRC value
                break
    return buf

def print_usage():
    print('Info : Extracts specified frames from a debug bitstream and creates a partial bitstream')
    print('Usage: ' + sys.argv[0] + ' <input_bitstream_file> [addr1, addr2, ...]')

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print_usage()
        exit(1)

    bin_file_name = sys.argv[1]
    faddr_list = sys.argv[2:]

    faddr_list.sort()

    fout = open(bin_file_name + '.partial', 'wb')
    for cmd in INIT_COMMANDS:
        fout.write(cmd.to_bytes(4, ENDIAN))

    fout.write(FRAME_ADDR_CMD.to_bytes(4, ENDIAN))
    fout.write(int(faddr_list[0], 16).to_bytes(4, ENDIAN))

    with open(bin_file_name, 'rb') as f:
        buf = b''
        for faddr in faddr_list:
            # fout.write(FRAME_ADDR_CMD.to_bytes(4, ENDIAN))
            # fout.write(int(faddr, 16).to_bytes(4, ENDIAN))
            buf = extract_frame(f, int(faddr, 16))
            fout.write(buf)
        fout.write(buf)

    for cmd in END_COMMANDS:
        fout.write(cmd.to_bytes(4, ENDIAN))

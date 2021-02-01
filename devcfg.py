import mmap
import os
import time

WORDS_PER_FRAME = 101
GLBL_SRC_ADDR = 0x18000000
GLBL_DST_ADDR = 0x18800000

class DevC:
    DEVC_ADDR           = 0xf8007000
    DEVC_ADDR_RANGE     = 0x100
    DMA_INVALID_ADDR    = 0xffffffff

    # Register offsets

    CTRL_REG            = 0x00
    LOCK_REG            = 0x04
    INT_STS_REG         = 0x0c
    INT_MASK_REG        = 0x10
    STATUS_REG          = 0x14
    DMA_SRC_ADDR_REG    = 0x18
    DMA_DST_ADDR_REG    = 0x1c
    DMA_SRC_LEN_REG     = 0x20
    DMA_DST_LEN_REG     = 0x24
    UNLOCK_REG          = 0x34
    MCTRL_REG           = 0x80

    # Control Register Bits

    CTRL_PCFG_PROG_B_MASK   = (1 << 30)
    CTRL_PCAP_PR_MASK       = (1 << 27)
    CTRL_PCAP_MODE_MASK     = (1 << 26)
    CTRL_PCAP_RATE_EN_MASK  = (1 << 25)
    CTRL_SEC_EN_MASK        = (1 << 7)

    # Miscellaneous Contrl Register Bits

    MCTRL_PCAP_LPBK_MASK    = (1 << 4)

    # Status Register Bits

    STATUS_DMA_Q_F          = (1 << 31)
    STATUS_DMA_Q_E          = (1 << 30)
    STATUS_PCFG_INIT_MASK   = (1 << 4)

    # Interrupt Status/Mask Register Bits

    IXR_DMA_DONE_MASK       = (1 << 13)
    IXR_D_P_DONE_MASK       = (1 << 12)
    IXR_PCFG_DONE_MASK      = (1 << 2)
    IXR_ERROR_FLAGS_MASK    = 0x00f0c860
    IXR_ALL_MASK            = 0xf8f7f87f

    def __init__(self):
        fd = os.open("/dev/mem", os.O_RDWR | os.O_SYNC)
        self.mm = mmap.mmap(fd, self.DEVC_ADDR_RANGE, mmap.MAP_SHARED,
                mmap.PROT_READ | mmap.PROT_WRITE, offset=self.DEVC_ADDR)
        os.close(fd)

    def read(self, reg_offset):
        #time.sleep(0.1)
        self.mm.seek(reg_offset)
        return int.from_bytes(self.mm.read(4), "little")

    def write(self, reg_offset, val):
        #time.sleep(0.1)
        self.mm.seek(reg_offset)
        self.mm.write(val.to_bytes(4, "little"))

    def is_dma_busy(self):
        val = self.read(DevC.STATUS_REG)
        return (val & DevC.STATUS_DMA_Q_F == DevC.STATUS_DMA_Q_F)

    def is_dma_err(self):
        val = self.read(DevC.INT_STS_REG)
        return (val & DevC.IXR_ERROR_FLAGS_MASK != 0)

    def intr_enable(self, mask):
        val = self.read(DevC.INT_MASK_REG)
        val &= ~(mask & DevC.IXR_ALL_MASK)
        self.write(DevC.INT_MASK_REG, val)

    def intr_disable(self, mask):
        val = self.read(DevC.INT_MASK_REG)
        val |= (mask & DevC.IXR_ALL_MASK)
        self.write(DevC.INT_MASK_REG, val)

    def intr_get_enabled(self):
        return ~ (self.read(DevC.INT_MASK_REG))

    def initiate_dma(self, src_addr, dst_addr, src_len, dst_len):
        self.write(DevC.DMA_SRC_ADDR_REG, src_addr)
        self.write(DevC.DMA_DST_ADDR_REG, dst_addr)
        self.write(DevC.DMA_SRC_LEN_REG, src_len)
        self.write(DevC.DMA_DST_LEN_REG, dst_len)

    def pcap_readback(self, src_addr, src_len, dst_addr, dst_len):

        # Clear internal PCAP loopback
        mctrl = self.read(DevC.MCTRL_REG)
        self.write(DevC.MCTRL_REG, (mctrl & ~DevC.MCTRL_PCAP_LPBK_MASK))

        self.initiate_dma(src_addr, DevC.DMA_INVALID_ADDR, src_len, 0)

        intr = self.intr_get_enabled()
        self.intr_disable(DevC.IXR_ALL_MASK)
        val = self.read(DevC.INT_STS_REG)
        while (val & DevC.IXR_D_P_DONE_MASK) != DevC.IXR_D_P_DONE_MASK:
            val = self.read(DevC.INT_STS_REG)
        self.intr_enable(intr)

        self.initiate_dma(DevC.DMA_INVALID_ADDR, dst_addr, 0, dst_len)

    def pcap_write(self, src_addr, src_len, dst_addr, dst_len):

        # Clear internal PCAP loopback
        mctrl = self.read(DevC.MCTRL_REG)
        self.write(DevC.MCTRL_REG, (mctrl & ~DevC.MCTRL_PCAP_LPBK_MASK))

        # Clear QUARTER_PCAP_RATE_EN bit for faster transfer
        ctrl = self.read(DevC.CTRL_REG)
        self.write(DevC.CTRL_REG, (ctrl & ~DevC.CTRL_PCAP_RATE_EN_MASK))

        self.initiate_dma(src_addr, dst_addr, src_len, dst_len)


def dump_regs(devc):
    print('============================')
    print('STATUS_REG  : ' + hex(devc.read(DevC.STATUS_REG)))
    print('MCTRL_REG   : ' + hex(devc.read(DevC.MCTRL_REG)))
    print('CTRL_REG    : ' + hex(devc.read(DevC.CTRL_REG)))
    print('INT_STS_REG : ' + hex(devc.read(DevC.INT_STS_REG)))

def pcap_enable(devc):
    ctrl = devc.read(DevC.CTRL_REG) 
    devc.write(DevC.CTRL_REG,
            ctrl | DevC.CTRL_PCAP_PR_MASK | DevC.CTRL_PCAP_MODE_MASK)

def store_cmd_seq(seq, addr):
    fd = os.open("/dev/mem", os.O_RDWR | os.O_SYNC)
    mm = mmap.mmap(fd, len(seq) * 4 + 4, mmap.MAP_SHARED,
            mmap.PROT_READ | mmap.PROT_WRITE, offset=addr)
    os.close(fd)
    for word in seq:
        mm.write(word.to_bytes(4, "little"))

def pcap_reg_read(devc):
    IDCODE_READ_SEQ = [
            0xffffffff,
            0xffffffff,
            0xffffffff,
            0xffffffff,
            0xffffffff,
            0xffffffff,
            0xffffffff,
            0xffffffff,
            0x000000bb,
            0x11220044,
            0xffffffff,
            0xaa995566,
            0x20000000,
            0x28018001,
            0x20000000,
            0x20000000 ]

    END_READ_SEQ = [
            0x30008001,
            0x0000000d,
            0x20000000,
            0x20000000,
            0x20000000,
            0x20000000 ]

    store_cmd_seq(IDCODE_READ_SEQ, GLBL_SRC_ADDR)
    devc.pcap_readback(GLBL_SRC_ADDR, len(IDCODE_READ_SEQ), GLBL_DST_ADDR, 1)

    time.sleep(0.1)

    store_cmd_seq(END_READ_SEQ, GLBL_SRC_ADDR)
    devc.initiate_dma(GLBL_SRC_ADDR, DevC.DMA_INVALID_ADDR, len(END_READ_SEQ), 0) 

def pcap_bitstream_read(devc, frame_addr, num_frames):
    num_frame_words = num_frames * WORDS_PER_FRAME

    BITSTREAM_READ_SEQ = [
            0xffffffff,
            0xffffffff,
            0xffffffff,
            0xffffffff,
            0x000000bb,
            0x11220044,
            0xffffffff,
            0xaa995566,

            0x20000000,
            0x20000000,

            #0x30008001,
            #0x0000000b,     # SHUTDOWN command
            #0x20000000,

            0x30008001,
            0x00000007,     # Reset CRC command
            0x20000000,

            0x20000000,
            0x20000000,
            0x20000000,
            0x20000000,
            0x20000000,

            0x30008001,
            0x00000004,
            0x20000000,

            0x20000000,
            0x20000000,

            0x30002001,
            frame_addr,     # Address for FAR
            0x28006000,
            0x48000000 | (num_frame_words + WORDS_PER_FRAME),
            0x20000000,
            0x20000000 ] 

    for i in range(32):
        BITSTREAM_READ_SEQ.append(0x20000000)

    END_READ_SEQ = [
            0x20000000,

            0x30008001,
            0x00000005,     # START command
            0x20000000,

            0x30008001,
            0x00000007,     # Reset CRC Command
            0x20000000,

            0x30008001,
            0x0000000d,
            0x20000000,
            0x20000000 ]

    #addr = GLBL_DST_ADDR
    #for i in range(NUM_FRAME_WORDS * 2):
        #os.system('memtool -4 -W 0xdeadbeef ' + hex(addr))
        #addr += 4

    os.system('memtool -4 -W 0xdf0d 0xf8000008')
    os.system('memtool -4 -W 0x701  0xf8000168')
    os.system('memtool -4 -W 0x767b 0xf8000004')

    store_cmd_seq(BITSTREAM_READ_SEQ, GLBL_SRC_ADDR)
    devc.pcap_readback(GLBL_SRC_ADDR, len(BITSTREAM_READ_SEQ),
            GLBL_DST_ADDR, num_frame_words + WORDS_PER_FRAME)

    time.sleep(0.1)

    store_cmd_seq(END_READ_SEQ, GLBL_SRC_ADDR)
    devc.initiate_dma(GLBL_SRC_ADDR, DevC.DMA_INVALID_ADDR, len(END_READ_SEQ), 0) 

    devc.write(DevC.INT_STS_REG,
        (DevC.IXR_PCFG_DONE_MASK | DevC.IXR_D_P_DONE_MASK | DevC.IXR_DMA_DONE_MASK))

def pcap_bitstream_write(devc, fname):
    seq = []
    with open(fname, 'rb') as f:
        while True:
            word = f.read(4)
            if word == b'':
                break
            seq.append(int.from_bytes(word, 'little'))

    store_cmd_seq(seq, GLBL_SRC_ADDR)
    devc.pcap_write(GLBL_SRC_ADDR, len(seq), DevC.DMA_INVALID_ADDR, 0)

    time.sleep(0.5)

    devc.write(DevC.INT_STS_REG,
        (DevC.IXR_PCFG_DONE_MASK | DevC.IXR_D_P_DONE_MASK | DevC.IXR_DMA_DONE_MASK))

def print_usage_exit(err):
    print("Usage: sudo python devcfg.py [read|write] <args>")
    print("       sudo python devcfg.py read <frame_addr> <num_frames>")
    print("       sudo python devcfg.py write <bitfile_name>")
    exit(err)

if __name__ == "__main__":

    devc = DevC()

    pcap_enable(devc)
    dump_regs(devc)

    # Clear interrupts
    devc.write(DevC.INT_STS_REG, 0xffffffff)

    if devc.is_dma_busy():
        print('Error: DMA is busy')
        exit(1)

    if devc.is_dma_err():
        print('Error: DMA reported error')
        dump_regs(devc)
        exit(1)

    if len(sys.argv) <= 2:
        print_usage_exit(1)

    if sys.argv[1] == 'read':
        if len(sys.argv) != 4:
            print('Invalid number of arguments!')
            print_usage_exit(1)
        pcap_bitstream_read(devc, int(sys.argv[2]), int(sys.argv[3])) 

    elif sys.argv[1] == 'write':
        if len(sys.argv) != 3:
            print('Invalid number of arguments!')
            print_usage_exit(1)
        pcap_bitstream_write(devc, sys.argv[2])

    else:
        print_usage_exit(1)
 
    dump_regs(devc)

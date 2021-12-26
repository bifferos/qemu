/*
 * Emulation of r6040 ethernet controller found in a number of SoCs.
 * Copyright (c) 2011 Mark Kelly, mark@bifferos.com
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
 * NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
 * THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * This has been written using the R8610[1] and ip101a[2] datasheets.
 *
 * ICs with the embedded controller include R8610, R3210, AMRISC20000
 * and Vortex86SX
 *
 * The emulation seems good enough to fool Linux 2.6.37.6.  It is
 * not perfect, but has proven useful.
 *
 * [1] http://www.sima.com.tw/download/R8610_D06_20051003.pdf
 * [2] http://www.icplus.com.tw/pp-IP101A.html
 */

#include "qemu/osdep.h"

#include "hw/pci/pci.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"
#include "net/net.h"
#include "sysemu/sysemu.h"
#include "qemu/timer.h"

/* #define DEBUG_R6040 1 */


#if defined DEBUG_R6040
#define DPRINTF(fmt, ...) \
    do { fprintf(stderr, "R6040: " fmt, ## __VA_ARGS__); } while (0)
#else
static inline GCC_FMT_ATTR(1, 2) int DPRINTF(const char *fmt, ...)
{
    return 0;
}
#endif

#define TYPE_R6040 "r6040"

OBJECT_DECLARE_SIMPLE_TYPE(R6040State, R6040)

/* Cast in order of appearance.  _W suffix means it's used to index the
   register word array (regs_w)
 */

#define MPSCCR_W         (0x88 / 2)

#define MAC0_W           (0x68 / 2)
#define MAC1_W           (0x6a / 2)
#define MAC2_W           (0x6c / 2)


#define RX_START_LOW_W   (0x34 / 2)
#define RX_START_HIGH_W  (0x38 / 2)
#define TX_PKT_COUNT_W   (0x5a / 2)
#define RX_PKT_COUNT_W   (0x50 / 2)


#define MCR0_W           (0x00 / 2)
#define MCR1_W           (0x04 / 2)
#define BIT_MRST         (1 << 0)

#define MTPR_W           (0x14 / 2)
#define MRBSR_W          (0x18 / 2)
#define MISR_W           (0x3c / 2)
#define MIER_W           (0x40 / 2)

#define MMDIO_W          (0x20 / 2)
#define MDIO_READ_W      (0x24 / 2)
#define MDIO_WRITE_W     (0x28 / 2)

#define MRCNT_W          (0x50 / 2)
#define MTCNT_W          (0x5c / 2)


#define MDIO_WRITE      0x4000
#define MDIO_READ       0x2000


typedef struct R6040State {
    PCIDevice dev;
    NICState *nic;
    NICConf conf;

    /* PHY related register sets */
    uint16_t mid0[3];
    uint16_t phy_regs[32];
    uint32_t phy_op_in_progress;

    /* Primary IO address space */
    union {
        uint8_t regs_b[0x100];   /* Byte access */
        uint16_t regs_w[0x100/2];  /* word access */
        uint32_t regs_l[0x100/4];  /* DWORD access */
    };
    QEMUTimer *timer;

    MemoryRegion bar_io;
    MemoryRegion bar_mem;
} R6040State;


/* some inlines to help access above structure */
static inline uint32_t TX_START(R6040State *s)
{
    uint32_t tmp = s->regs_w[0x2c/2];
    return tmp | (s->regs_w[0x30/2] << 16);
}

static inline void TX_START_SET(R6040State *s, uint32_t start)
{
    s->regs_w[0x2c/2] = start & 0xffff;
    s->regs_w[0x30/2] = (start >> 16) & 0xffff;
}

static inline uint32_t RX_START(R6040State *s)
{
    uint32_t tmp = s->regs_w[0x34/2];
    return tmp | (s->regs_w[0x38/2] << 16);
}

static inline void RX_START_SET(R6040State *s, uint32_t start)
{
    s->regs_w[0x34/2] = start & 0xffff;
    s->regs_w[0x38/2] = (start >> 16) & 0xffff;
}


static void r6040_update_irq(R6040State *s)
{
    PCIDevice *d = PCI_DEVICE(s);
    uint16_t isr = s->regs_w[MISR_W] & s->regs_w[MIER_W];

    pci_set_irq(d, (isr != 0));
}


/* Mark auto-neg complete, NIC up.  */
static void PhysicalLinkUp(void *opaque)
{
    R6040State *s = opaque;
    s->phy_regs[1] |= (1 << 2);
    timer_del(s->timer);
    timer_free(s->timer);
}


/* Transmit and receive descriptors are doubled up
   One is a subset of the other anyhow
 */
typedef struct Descriptor {
    uint16_t dst;
    uint16_t dlen;
    uint32_t dbp;
    uint32_t dnx;
    uint16_t hidx;
    uint16_t reserved_1;
    uint16_t reserved_2;
} Descriptor;


/* Some debugging functions */

#ifdef DEBUG_R6040
static void addr_dump16(const char *name, uint16_t val)
{
    DPRINTF("%s: 0x%04x  ", name, val);
}

static void addr_dump32(const char *name, uint32_t val)
{
    DPRINTF("%s: 0x%x  ", name, val);
}

static void hex_dump(const uint8_t *data, uint32_t len)
{
    uint8_t i;
    DPRINTF("hex: ");
    for (i = 0; i < len; i++) {
        fprintf(stderr, "%02x ", *data);
        if (i && !(i % 0x20)) {
            fprintf(stderr, "\n");
        }
        data++;
    }
    fprintf(stderr, "\n");
}

static void desc_dump(Descriptor *d, uint32_t addr)
{
    DPRINTF("\nDumping: 0x%x\n", addr);
    addr_dump16("DST", d->dst);
    addr_dump16("DLEN", d->dlen);
    addr_dump32("DBP", (unsigned long)d->dbp);
    addr_dump32("DNX", (unsigned long)d->dnx);
    addr_dump16("HIDX", d->hidx);
    printf("\n");
}

static void dump_phys_mem(uint32_t addr, int len)
{
    uint8_t buffer[1024];
    cpu_physical_memory_read(addr, buffer, len);
    hex_dump(buffer, len);
}

static void dump_pci(uint8_t *pci_conf)
{
    uint32_t *p = (uint32_t *)pci_conf;
    int i = 0;
    for (i = 0; i < 0x40; i += 4) {
        DPRINTF("Addr: 0x%08x,  Data: 0x%08x\n", i, *p);
        p++;
    }
}
#endif


static const VMStateDescription vmstate_r6040 = {
    .name = "r6040",
    .version_id = 3,
    .minimum_version_id = 2,
    .minimum_version_id_old = 2,
    .fields = (VMStateField[]) {
        VMSTATE_PCI_DEVICE(dev, R6040State),
        VMSTATE_BUFFER(regs_b, R6040State),
        VMSTATE_UINT16_ARRAY(mid0, R6040State, 3),
        VMSTATE_UINT16_ARRAY(phy_regs, R6040State, 32),
        VMSTATE_UINT32(phy_op_in_progress, R6040State),
        VMSTATE_MACADDR(conf.macaddr, R6040State),
        VMSTATE_END_OF_LIST()
    }
};


static int TryToSendOnePacket(void *opaque)
{
    R6040State *s = opaque;
    Descriptor d;
    uint8_t pkt_buffer[2000];
    uint32_t tocopy;

    cpu_physical_memory_read(TX_START(s), (uint8_t *)&d, sizeof(d));

    if (d.dst & 0x8000) {    /* MAC owns it? */
        tocopy = d.dlen;
        if (tocopy > sizeof(pkt_buffer)) {
            tocopy = sizeof(pkt_buffer);
        }
        /* copy the packet to send it */
        cpu_physical_memory_read(d.dbp, pkt_buffer, tocopy);

        qemu_send_packet(qemu_get_queue(s->nic), pkt_buffer, tocopy);
        s->regs_w[TX_PKT_COUNT_W]++;

        /* relinquish ownership, we're done with it */
        d.dst &= ~0x8000;

        /* Copy the new version of the descriptor back */
        cpu_physical_memory_write(TX_START(s), (uint8_t *)&d, sizeof(d));

        /* Advance to the next buffer if packet processed */
        TX_START_SET(s, d.dnx);

        return 1;
    }

    return 0;
}


static void r6040_transmit(void *opaque)
{
    R6040State *s = opaque;
    int count = 0;

    while (TryToSendOnePacket(s)) {
        ++count;
    }

    if (count) {
        s->regs_w[MISR_W] |= 0x10;
        r6040_update_irq(s);
    }
}


/* Whether to allow callback returning 1 for yes, can receive */
static bool r6040_can_receive(NetClientState *nc)
{
    R6040State *s = qemu_get_nic_opaque(nc);
    return s->regs_w[0] & 0x0002;
}


static int ReceiveOnePacket(void *opaque, const uint8_t *buf, size_t len)
{
    R6040State *s = opaque;
    uint32_t tocopy = len+4;  /* include checksum */
    Descriptor d;

    cpu_physical_memory_read(RX_START(s), (uint8_t *)&d, sizeof(Descriptor));
    /*desc_dump(&d, 0);*/

    if (d.dst & 0x8000) {    /* MAC owned? */

        uint16_t max_buffer = s->regs_w[MRBSR_W] & 0x07fc;
        if (tocopy > max_buffer) {
            tocopy = max_buffer;
        }

        cpu_physical_memory_write(d.dbp, buf, tocopy-4);

        /* indicate received OK */
        d.dst |= (1 << 14);
        d.dlen = tocopy;
        /* relinquish ownership */
        d.dst &= ~0x8000;

        /* Copy the descriptor back */
        cpu_physical_memory_write(RX_START(s), (uint8_t *)&d,
                                   sizeof(Descriptor));

        s->regs_w[RX_PKT_COUNT_W]++;

        s->regs_w[MISR_W] |= 1;  /* received pkt interrupt */

        r6040_update_irq(s);

        RX_START_SET(s, d.dnx);  /* advance */

        return 0;
    }
    return -1;
}


/* called on incoming packets */
static ssize_t r6040_receive(NetClientState *nc, const uint8_t *buf,
                                        size_t len)
{
    R6040State *s = qemu_get_nic_opaque(nc);
    DPRINTF("Received incoming packet of len %ld\n", len);

    if (0 == ReceiveOnePacket(s, buf, len)) {
        return len;  /* copied OK */
    }

    return 0;
}


static inline int BIT_SET(uint16_t old, uint16_t new, uint16_t bit)
{
    uint16_t before = (old & (1 << bit));
    uint16_t after = (new & (1 << bit));
    if (!before && after) {
        return 1;
    }
    return 0;
}


static void r6040_ioport_writew(void *opaque, uint32_t addr, uint32_t val)
{
    R6040State *s = opaque;
    uint16_t old;
    addr &= 0xff;   /* get relative to base address */
    addr /= 2;    /* Get the offset into the word-array */
    old = s->regs_w[addr];   /* store the old value for future use */

    switch (addr) {
    case MCR0_W:   /* 0x00 */
        if (BIT_SET(old, val, 12)) {
            r6040_transmit(opaque);
        }
        break;
    case MCR1_W:  /* 0x04 */
        if (val & BIT_MRST) {   /* reset request incoming */
            /* reset requested, complete it immediately, set this value to
               default */
            val = 0x0010;
        }
        break;
    case MTPR_W:  /* TX command reg, 0x14 */
        if (val & 1) {
            r6040_transmit(opaque);
            val &= ~1;
        }
        break;
    case MMDIO_W:  /* MDIO control, 0x20 */
        {
            int phy_exists = ((val & 0x1f00) == 0x100) ? 1 : 0;
            uint16_t *phy = s->phy_regs;
            phy += (val & 0x1f);

            if  (val & (1 << 13)) {   /* read data */
                if (phy_exists) {
                    s->regs_w[MDIO_READ_W] = *phy;
                } else {
                    s->regs_w[MDIO_READ_W] = 0xffff;
                }
            } else if (val & (1 << 14)) {  /* write data */
                if (phy_exists) {
                    *phy = s->regs_w[MDIO_WRITE_W];
                }
            }

            /* Whether you request to read or write, both bits go high while
               the operation is in progress, e.g. tell it to read, and the
               write-in-progress flag also goes high */
            val |= 0x6000;  /* signal operation has started */
            s->phy_op_in_progress = 1;

            break;
        }
    case MISR_W:  /* interrupt status reg (read to clear), 0x3c */
        return;

    case MIER_W:  /* interrupt enable register, 0x40 */
        s->regs_w[MIER_W] = val;
        r6040_update_irq(s);
        return;

    case MRCNT_W:   /* 0x50 */
    case MTCNT_W:   /* 0x5c */
        return;  /* Can't write to pkt count registers, skip */

    }
    s->regs_w[addr] = val & 0xFFFF;
}


static uint32_t r6040_ioport_readw(void *opaque, uint32_t addr)
{
    R6040State *s = opaque;
    addr &= 0xff;   /* get relative to base address */
    addr /= 2;    /* Get the offset into the word-array */
    uint32_t tmp = s->regs_w[addr];  /* get the value */

    switch (addr) {

    case MMDIO_W:  /* MDIO control, 0x20 */
        {
            /* Clear any in-progress MDIO activity for the next read
               This simulates the polling of the MDIO operation status,
               so the driver code always has to read the register twice
               before it thinks the operation is complete. */
            if (s->phy_op_in_progress) {
                s->regs_w[addr] &= ~0x6000;
                s->phy_op_in_progress = 0;
            }
            break;
        }
    case MISR_W:  /* interrupt status reg (read to clear)  0x3c */
        s->regs_w[addr] = 0;
        break;
    case MIER_W:  /* interrupt enable reg 0x40 */
        break;
    case MRCNT_W:  /* 0x50 */
    case MTCNT_W:  /* 0x5c */
        s->regs_w[addr] = 0;   /* read to clear */
        break;
    default:
        break;
    }
    return tmp;
}


/* byte and long access are routed via the word operation handlers */
static void r6040_ioport_writeb(void *opaque, uint32_t addr, uint32_t val)
{
    R6040State *s = opaque;
    addr &= 0xFF;
    val &= 0xFF;
    uint16_t old = s->regs_w[addr/2];  /* get the current value */
    if (addr & 1) {
        old &= 0xff;
        old |= (val << 8);
    } else {
        old &= 0xff00;
        old |= val;
    }

    r6040_ioport_writew(opaque, addr, old);  /* call the word-based version */
}

static void r6040_ioport_writel(void *opaque, uint32_t addr, uint32_t val)
{
    /* Set the low value */
    r6040_ioport_writew(opaque, addr, val & 0xffff);
    /* Set the high value */
    r6040_ioport_writew(opaque, addr+2, (val >> 16) & 0xffff);
}

static uint32_t r6040_ioport_readb(void *opaque, uint32_t addr)
{
    uint32_t tmp = r6040_ioport_readw(opaque, addr & ~1);
    if (addr & 1) {
        return (tmp & 0xff00) >> 8;
    }
    return tmp & 0xff;
}

static uint32_t r6040_ioport_readl(void *opaque, uint32_t addr)
{
    uint32_t tmp = r6040_ioport_readw(opaque, addr);
    return tmp | (r6040_ioport_readw(opaque, addr+2) << 16);
}

static void r6040_ioport_write(void *opaque, hwaddr addr,
                                 uint64_t val, unsigned size)
{
    switch (size) {
    case 1:
        r6040_ioport_writeb(opaque, addr, val);
        break;
    case 2:
        r6040_ioport_writew(opaque, addr, val);
        break;
    case 4:
        r6040_ioport_writel(opaque, addr, val);
        break;
    }
}

static uint64_t r6040_ioport_read(void *opaque, hwaddr addr,
                                  unsigned size)
{
    switch (size) {
    case 1:
        return r6040_ioport_readb(opaque, addr);
    case 2:
        return r6040_ioport_readw(opaque, addr);
    case 4:
        return r6040_ioport_readl(opaque, addr);
    }

    return -1;
}

static const MemoryRegionOps rtl8139_io_ops = {
    .read = r6040_ioport_read,
    .write = r6040_ioport_write,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
    .endianness = DEVICE_LITTLE_ENDIAN,
};


static NetClientInfo net_r6040_info = {
    .type = NET_CLIENT_DRIVER_NIC,
    .size = sizeof(NICState),
    .can_receive = r6040_can_receive,
    .receive = r6040_receive,
};


static void r6040_realize(PCIDevice *dev, Error **errp)
{
    R6040State *s = R6040(dev);
    uint8_t *pci_conf;

    /* MAC PHYS status change register.  Linux driver expects something
       sensible as default and if not will try to set it */
    s->regs_w[MPSCCR_W] = 0x9f07;

    /* Default value for maximum packet size */
    s->regs_w[MRBSR_W] = 0x600;

    /* set the MAC, linux driver reads this when it loads, it is
       normally set by the BIOS, but obviously Qemu BIOS isn't going
       to do that */
    s->regs_w[MAC0_W] = 0x5452;
    s->regs_w[MAC1_W] = 0x1200;
    s->regs_w[MAC2_W] = 0x5734;

    /* Tell Qemu the same thing */
    s->conf.macaddr.a[0] = s->regs_w[MAC0_W] & 0xff;
    s->conf.macaddr.a[1] = (s->regs_w[MAC0_W] >> 8) & 0xff;
    s->conf.macaddr.a[2] = s->regs_w[MAC1_W] & 0xff;
    s->conf.macaddr.a[3] = (s->regs_w[MAC1_W] >> 8) & 0xff;
    s->conf.macaddr.a[4] = s->regs_w[MAC2_W] & 0xff;
    s->conf.macaddr.a[5] = (s->regs_w[MAC2_W] >> 8) & 0xff;

    /* no commands running */
    s->phy_op_in_progress = 0;

    /* PHY auto-neg in progress */
    s->phy_regs[1] = 0x786d & ~(1 << 2);
    s->phy_regs[2] = 0x0243;
    s->phy_regs[3] = 0x0c54;

    pci_conf = (uint8_t *)s->dev.config;

    pci_conf[PCI_HEADER_TYPE] = PCI_HEADER_TYPE_NORMAL; /* header_type */
    pci_conf[PCI_INTERRUPT_LINE] = 0xa;     /* interrupt line  */
    pci_conf[PCI_INTERRUPT_PIN] = 1;      /* interrupt pin 0 */

    memory_region_init_io(&s->bar_io, OBJECT(s), &rtl8139_io_ops, s,
                          "r6040", 0x100);
    memory_region_init_alias(&s->bar_mem, OBJECT(s), "r6040-mem", &s->bar_io,
                             0, 0x100);

    pci_register_bar(&s->dev, 0, PCI_BASE_ADDRESS_SPACE_IO, &s->bar_io);
    pci_register_bar(&s->dev, 1, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->bar_mem);

    s->nic = qemu_new_nic(&net_r6040_info, &s->conf,
                          object_get_typename(OBJECT(dev)), DEVICE(dev)->id, s);

    qemu_format_nic_info_str(qemu_get_queue(s->nic), s->conf.macaddr.a);

    /* Simulate a delay of a couple of seconds for the link to come up.
       Not required for Linux but very handy for developing BIOS code.
     */
    s->timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, PhysicalLinkUp, s);
    timer_mod(s->timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 1500);
}

static Property r6040_properties[] = {
    DEFINE_NIC_PROPERTIES(R6040State, conf),
    DEFINE_PROP_END_OF_LIST(),
};

static void r6040_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = r6040_realize;
    k->exit = NULL;
    k->romfile = NULL;
    k->vendor_id = PCI_VENDOR_ID_RDC;
    k->device_id = PCI_DEVICE_ID_RDC_R6040;
    k->revision = 0;
    k->class_id = PCI_CLASS_NETWORK_ETHERNET;
    dc->reset = NULL;
    dc->vmsd = &vmstate_r6040;
    device_class_set_props(dc, r6040_properties);
    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
}


static const TypeInfo r6040_info = {
    .name          = TYPE_R6040,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(R6040State),
    .class_init    = r6040_class_init,
    .instance_init = NULL,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    },
};


static void r6040_register_types(void)
{
    type_register_static(&r6040_info);
}


type_init(r6040_register_types)

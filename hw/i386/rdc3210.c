/*
 * QEMU RDC3210 PC System Emulator
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include CONFIG_DEVICES

#include "qemu/units.h"
#include "hw/loader.h"
#include "hw/i386/x86.h"
#include "hw/i386/pc.h"
#include "hw/i386/apic.h"
#include "hw/pci-host/i440fx.h"
#include "hw/southbridge/piix.h"
#include "hw/display/ramfb.h"
#include "hw/firmware/smbios.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_ids.h"
#include "hw/usb.h"
#include "hw/ide/pci.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "net/net.h"
#include "sysemu/kvm.h"
#include "sysemu/block-backend.h"
#include "hw/kvm/clock.h"
#include "sysemu/sysemu.h"
#include "hw/sysbus.h"
#include "sysemu/arch_init.h"
#include "hw/i2c/smbus_eeprom.h"
#include "hw/xen/xen-x86.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"
#include "e820_memory_layout.h"
#include "hw/acpi/acpi.h"
#include "hw/acpi/pc-hotplug.h"
#include "cpu.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "sysemu/xen.h"
#include "migration/global_state.h"
#include "migration/misc.h"
#include "sysemu/numa.h"
#include "hw/hyperv/vmbus-bridge.h"
#include "hw/mem/nvdimm.h"
#include "hw/i386/acpi-build.h"

#define MAX_IDE_BUS 2

#define FLASH_EN29LV640_BASE (0xff800000)
#define FLASH_EN29LV640_SIZE (0x800000)
static void bifferboard_flash_init(PCMachineState *pcms,
                                   MemoryRegion *rom_memory)
{
    DriveInfo *dinfo;
    BlockBackend *blk;
    DeviceState *dev;

    dev = qdev_new(TYPE_PFLASH_CFI02);

    dinfo = drive_get(IF_PFLASH, 0, 0);
    blk = dinfo ? blk_by_legacy_dinfo(dinfo) : NULL;
    if (blk) {
        char devpath[100];
        hwaddr addr = (hwaddr)(FLASH_EN29LV640_BASE + FLASH_EN29LV640_SIZE - 64*1024);

        snprintf(devpath, sizeof(devpath), "/rom@" TARGET_FMT_plx, addr);
        add_boot_device_path(-1, NULL, devpath);

        /* Set blk as backing file */
        qdev_prop_set_drive(dev, "drive", blk);
    }
    else {
        warn_report("No firmware backing file set! Set one with '%s'",
                    "-drive file=firmware.img,if=pflash,format=raw");
        /* Try to load biffboot from "-bios" command line */
        x86_bios_rom_init(MACHINE(pcms), "bios.bin", rom_memory, false);
    }

    // Last 64K is organized as 8 * 8K
    qdev_prop_set_uint32(dev, "num-blocks0", (FLASH_EN29LV640_SIZE - 0x10000) / 0x10000);
    qdev_prop_set_uint32(dev, "sector-length0", 0x10000);
    qdev_prop_set_uint32(dev, "num-blocks1", 8);
    qdev_prop_set_uint32(dev, "sector-length1", 0x2000);
    qdev_prop_set_uint8(dev, "width", 2); // 16 bit
    qdev_prop_set_uint8(dev, "mappings", 1);
    qdev_prop_set_uint8(dev, "big-endian", 0);
    qdev_prop_set_uint16(dev, "id0", 0x007F);
    qdev_prop_set_uint16(dev, "id1", 0x22CB);
    qdev_prop_set_uint16(dev, "id2", 0x001C);
    qdev_prop_set_uint16(dev, "id3", 0x0000);
    qdev_prop_set_uint16(dev, "unlock-addr0", 0x0555);
    qdev_prop_set_uint16(dev, "unlock-addr1", 0x02aa);
    qdev_prop_set_string(dev, "name", "en29lv640.0");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);

    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, FLASH_EN29LV640_BASE);
}

static void rdc_memory_init(PCMachineState *pcms,
                            MemoryRegion *system_memory,
                            MemoryRegion *rom_memory,
                            MemoryRegion **ram_memory)
{
    MemoryRegion *ram_below_4g, *ram_above_4g;
    MachineState *machine = MACHINE(pcms);
    MachineClass *mc = MACHINE_GET_CLASS(machine);
    PCMachineClass *pcmc = PC_MACHINE_GET_CLASS(pcms);
    X86MachineState *x86ms = X86_MACHINE(pcms);

    assert(machine->ram_size == x86ms->below_4g_mem_size +
                                x86ms->above_4g_mem_size);

    /*
     * Split single memory region and use aliases to address portions of it,
     * done for backwards compatibility with older qemus.
     */
    *ram_memory = machine->ram;
    ram_below_4g = g_malloc(sizeof(*ram_below_4g));
    memory_region_init_alias(ram_below_4g, NULL, "ram-below-4g", machine->ram,
                             0, x86ms->below_4g_mem_size);
    memory_region_add_subregion(system_memory, 0, ram_below_4g);
    e820_add_entry(0, x86ms->below_4g_mem_size, E820_RAM);
    if (x86ms->above_4g_mem_size > 0) {
        ram_above_4g = g_malloc(sizeof(*ram_above_4g));
        memory_region_init_alias(ram_above_4g, NULL, "ram-above-4g",
                                 machine->ram,
                                 x86ms->below_4g_mem_size,
                                 x86ms->above_4g_mem_size);
        memory_region_add_subregion(system_memory, 0x100000000ULL,
                                    ram_above_4g);
        e820_add_entry(0x100000000ULL, x86ms->above_4g_mem_size, E820_RAM);
    }

    if (!pcmc->has_reserved_memory &&
        (machine->ram_slots ||
         (machine->maxram_size > machine->ram_size))) {

        error_report("\"-memory 'slots|maxmem'\" is not supported by: %s",
                     mc->name);
        exit(EXIT_FAILURE);
    }

    /* always allocate the device memory information */
    machine->device_memory = g_malloc0(sizeof(*machine->device_memory));

    /* initialize device memory address space */
    if (pcmc->has_reserved_memory &&
        (machine->ram_size < machine->maxram_size)) {
        ram_addr_t device_mem_size = machine->maxram_size - machine->ram_size;

        if (machine->ram_slots > ACPI_MAX_RAM_SLOTS) {
            error_report("unsupported amount of memory slots: %"PRIu64,
                         machine->ram_slots);
            exit(EXIT_FAILURE);
        }

        if (QEMU_ALIGN_UP(machine->maxram_size,
                          TARGET_PAGE_SIZE) != machine->maxram_size) {
            error_report("maximum memory size must by aligned to multiple of "
                         "%d bytes", TARGET_PAGE_SIZE);
            exit(EXIT_FAILURE);
        }

        machine->device_memory->base =
            ROUND_UP(0x100000000ULL + x86ms->above_4g_mem_size, 1 * GiB);

        if (pcmc->enforce_aligned_dimm) {
            /* size device region assuming 1G page max alignment per slot */
            device_mem_size += (1 * GiB) * machine->ram_slots;
        }

        if ((machine->device_memory->base + device_mem_size) <
            device_mem_size) {
            error_report("unsupported amount of maximum memory: " RAM_ADDR_FMT,
                         machine->maxram_size);
            exit(EXIT_FAILURE);
        }

        memory_region_init(&machine->device_memory->mr, OBJECT(pcms),
                           "device-memory", device_mem_size);
        memory_region_add_subregion(system_memory, machine->device_memory->base,
                                    &machine->device_memory->mr);
    }

    bifferboard_flash_init(pcms, rom_memory);
    pc_system_flash_cleanup_unused(pcms);

    /* Init default IOAPIC address space */
    x86ms->ioapic_as = &address_space_memory;

    /* Init ACPI memory hotplug IO base address */
    pcms->memhp_io_base = ACPI_MEMORY_HOTPLUG_BASE;
}

/* PC hardware initialisation */
static void pc_init1(MachineState *machine,
                     const char *host_type, const char *pci_type)
{
    PCMachineState *pcms = PC_MACHINE(machine);
    PCMachineClass *pcmc = PC_MACHINE_GET_CLASS(pcms);
    X86MachineState *x86ms = X86_MACHINE(machine);
    MemoryRegion *system_memory = get_system_memory();
    MemoryRegion *system_io = get_system_io();
    PCIBus *pci_bus;
    PIIX3State *piix3;
    ISABus *isa_bus;
    PCII440FXState *i440fx_state;
    int piix3_devfn = -1;
    GSIState *gsi_state;
    ISADevice *rtc_state;
    MemoryRegion *ram_memory;
    MemoryRegion *pci_memory;
    MemoryRegion *rom_memory;
    ram_addr_t lowmem;

    /*
     * Calculate ram split, for memory below and above 4G.  It's a bit
     * complicated for backward compatibility reasons ...
     *
     *  - Traditional split is 3.5G (lowmem = 0xe0000000).  This is the
     *    default value for max_ram_below_4g now.
     *
     *  - Then, to gigabyte align the memory, we move the split to 3G
     *    (lowmem = 0xc0000000).  But only in case we have to split in
     *    the first place, i.e. ram_size is larger than (traditional)
     *    lowmem.  And for new machine types (gigabyte_align = true)
     *    only, for live migration compatibility reasons.
     *
     *  - Next the max-ram-below-4g option was added, which allowed to
     *    reduce lowmem to a smaller value, to allow a larger PCI I/O
     *    window below 4G.  qemu doesn't enforce gigabyte alignment here,
     *    but prints a warning.
     *
     *  - Finally max-ram-below-4g got updated to also allow raising lowmem,
     *    so legacy non-PAE guests can get as much memory as possible in
     *    the 32bit address space below 4G.
     *
     *  - Note that Xen has its own ram setup code in xen_ram_init(),
     *    called via xen_hvm_init_pc().
     *
     * Examples:
     *    qemu -M pc-1.7 -m 4G    (old default)    -> 3584M low,  512M high
     *    qemu -M pc -m 4G        (new default)    -> 3072M low, 1024M high
     *    qemu -M pc,max-ram-below-4g=2G -m 4G     -> 2048M low, 2048M high
     *    qemu -M pc,max-ram-below-4g=4G -m 3968M  -> 3968M low (=4G-128M)
     */
    if (!pcms->max_ram_below_4g) {
        pcms->max_ram_below_4g = 0xe0000000; /* default: 3.5G */
    }
    lowmem = pcms->max_ram_below_4g;
    if (machine->ram_size >= pcms->max_ram_below_4g) {
        if (pcmc->gigabyte_align) {
            if (lowmem > 0xc0000000) {
                lowmem = 0xc0000000;
            }
            if (lowmem & (1 * GiB - 1)) {
                warn_report("Large machine and max_ram_below_4g "
                            "(%" PRIu64 ") not a multiple of 1G; "
                            "possible bad performance.",
                            pcms->max_ram_below_4g);
            }
        }
    }

    if (machine->ram_size >= lowmem) {
        x86ms->above_4g_mem_size = machine->ram_size - lowmem;
        x86ms->below_4g_mem_size = lowmem;
    } else {
        x86ms->above_4g_mem_size = 0;
        x86ms->below_4g_mem_size = machine->ram_size;
    }

    x86_cpus_init(x86ms, pcmc->default_cpu_version);

    if (pcmc->kvmclock_enabled) {
        kvmclock_create(pcmc->kvmclock_create_always);
    }

    pci_memory = g_new(MemoryRegion, 1);
    memory_region_init(pci_memory, NULL, "pci", UINT64_MAX);
    rom_memory = pci_memory;

    pc_guest_info_init(pcms);

    if (pcmc->smbios_defaults) {
        MachineClass *mc = MACHINE_GET_CLASS(machine);
        /* These values are guest ABI, do not change */
        smbios_set_defaults("QEMU", "Standard PC (i440FX + PIIX, 1996)",
                            mc->name, pcmc->smbios_legacy_mode,
                            pcmc->smbios_uuid_encoded,
                            SMBIOS_ENTRY_POINT_21);
    }

    /* allocate ram and load rom/bios */
    rdc_memory_init(pcms, system_memory, rom_memory, &ram_memory);

    gsi_state = pc_gsi_create(&x86ms->gsi, pcmc->pci_enabled);

    pci_bus = i440fx_init(host_type,
                          pci_type,
                          &i440fx_state,
                          system_memory, system_io, machine->ram_size,
                          x86ms->below_4g_mem_size,
                          x86ms->above_4g_mem_size,
                          pci_memory, ram_memory);
    pcms->bus = pci_bus;

    piix3 = piix3_create(pci_bus, &isa_bus);
    piix3->pic = x86ms->gsi;
    piix3_devfn = piix3->dev.devfn;

    isa_bus_irqs(isa_bus, x86ms->gsi);

    pc_i8259_create(isa_bus, gsi_state->i8259_irq);

    ioapic_init_gsi(gsi_state, "i440fx");

    if (tcg_enabled()) {
        x86_register_ferr_irq(x86ms->gsi[13]);
    }

    assert(pcms->vmport != ON_OFF_AUTO__MAX);
    if (pcms->vmport == ON_OFF_AUTO_AUTO) {
        pcms->vmport = xen_enabled() ? ON_OFF_AUTO_OFF : ON_OFF_AUTO_ON;
    }

    /* init basic PC hardware */
    pc_basic_device_init(pcms, isa_bus, x86ms->gsi, &rtc_state, true,
                         0x4);

    pc_nic_init(pcmc, isa_bus, pci_bus);

    if (pcmc->pci_enabled) {
        PCIDevice *dev;
        BusState *idebus[MAX_IDE_BUS];

        dev = pci_create_simple(pci_bus, piix3_devfn + 1,
                                xen_enabled() ? "piix3-ide-xen" : "piix3-ide");
        pci_ide_create_devs(dev);
        idebus[0] = qdev_get_child_bus(&dev->qdev, "ide.0");
        idebus[1] = qdev_get_child_bus(&dev->qdev, "ide.1");
        pc_cmos_init(pcms, idebus[0], idebus[1], rtc_state);
    }

    if (pcmc->pci_enabled && machine_usb(machine)) {
        pci_create_simple(pci_bus, piix3_devfn + 2, "pci-ohci");
    }

    if (pcmc->pci_enabled && x86_machine_is_acpi_enabled(X86_MACHINE(pcms))) {
        DeviceState *piix4_pm;
        qemu_irq smi_irq;

        smi_irq = qemu_allocate_irq(pc_acpi_smi_interrupt, first_cpu, 0);
        /* TODO: Populate SPD eeprom data.  */
        pcms->smbus = piix4_pm_init(pci_bus, piix3_devfn + 3, 0xb100,
                                    x86ms->gsi[9], smi_irq,
                                    x86_machine_is_smm_enabled(x86ms),
                                    &piix4_pm);
        smbus_eeprom_init(pcms->smbus, 8, NULL, 0);

        object_property_add_link(OBJECT(machine), PC_MACHINE_ACPI_DEVICE_PROP,
                                 TYPE_HOTPLUG_HANDLER,
                                 (Object **)&x86ms->acpi_dev,
                                 object_property_allow_set_link,
                                 OBJ_PROP_LINK_STRONG);
        object_property_set_link(OBJECT(machine), PC_MACHINE_ACPI_DEVICE_PROP,
                                 OBJECT(piix4_pm), &error_abort);
    }
}

static void rdc3210_machine_options(MachineClass *m)
{
    PCMachineClass *pcmc = PC_MACHINE_CLASS(m);
    pcmc->default_nic_model = "e1000";
    m->family = "pc_piix";
    m->desc = "RDC3210";
    m->default_machine_opts = "firmware=bios-256k.bin";
    m->default_display = NULL;
    machine_class_allow_dynamic_sysbus_dev(m, TYPE_RAMFB_DEVICE);
    machine_class_allow_dynamic_sysbus_dev(m, TYPE_VMBUS_BRIDGE);
    m->alias = "rdc3210";
    m->is_default = false;
    pcmc->default_cpu_version = 1;
}

static void pc_init_rdc3210(MachineState *machine) \
{
    pc_init1(machine, TYPE_I440FX_PCI_HOST_BRIDGE,
             TYPE_I440FX_PCI_DEVICE);
}

DEFINE_PC_MACHINE(rdc3210, "rdc-3210", pc_init_rdc3210,
                  rdc3210_machine_options);

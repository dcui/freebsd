/*-		XXX: we mustn't copy GPLv2 to BSD.................
 * Copyright (c) 2016 Microsoft Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/smp.h>
#include <sys/sysctl.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>

#include <machine/bus.h>
#include <machine/resource.h>
#include <machine/frame.h>

#include <sys/bus.h>
#include <sys/rman.h>
#include <sys/mutex.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <machine/atomic.h>

#include <machine/intr_machdep.h>

#include <dev/hyperv/include/hyperv.h>
#include <dev/hyperv/include/hyperv_busdma.h>
#include <dev/hyperv/include/vmbus_xact.h>

#include "vmbus_if.h"

//FIXME..........
extern long lo_start, lo_end;
extern long hi_start, hi_end;

typedef struct hp_softc {
	int i;//TODO

} hp_softc_t;

/* {44C4F61D-4444-4400-9D52-802E27EDE19F} */
static const struct hyperv_guid g_pci_vsc_device_type = {
	.hv_guid = {0x1D, 0xF6, 0xC4, 0x44, 0x44, 0x44, 0x00, 0x44,
		0x9D, 0x52, 0x80, 0x2E, 0x27, 0xED, 0xE1, 0x9F}
};

/*
 * Standard probe entry point.
 *
 */
static int
pcivsc_probe(device_t dev)
{
	if (VMBUS_PROBE_GUID(device_get_parent(dev), dev,
	    &g_pci_vsc_device_type) == 0) {
		device_set_desc(dev, "Hyper-V PCI Express Pass Through");
		return BUS_PROBE_DEFAULT;
	}
	return ENXIO;
}

/*
 * Standard attach entry point.
 *
 * Called when the driver is loaded.  It allocates needed resources,
 * and initializes the "hardware" and software.
 */
static int
pcivsc_attach(device_t dev)
{
	hp_softc_t *sc;

	sc = device_get_softc(dev);

	printf("pcivsc_attach............: sc=%p\n", sc);
	return 0;
}

/*
 * Standard detach entry point
 */
static int
pcivsc_detach(device_t dev)
{
	struct hp_softc *sc = device_get_softc(dev);

	if (bootverbose)
		printf("pcivsc_detach!!!! TODO!!! sc=%p\n", sc);

	return 0;
}

/*
 * Standard shutdown entry point
 */
static int
pcivsc_shutdown(device_t dev)
{
	//TODO
	return 0;
}

static device_method_t pcivsc_methods[] = {
        /* Device interface */
        DEVMETHOD(device_probe,         pcivsc_probe),
        DEVMETHOD(device_attach,        pcivsc_attach),
        DEVMETHOD(device_detach,        pcivsc_detach),
        DEVMETHOD(device_shutdown,      pcivsc_shutdown),

        { 0, 0 }
};

static driver_t pcivsc_driver = {
        "hp",
        pcivsc_methods,
        sizeof(hp_softc_t)
};

static devclass_t pcivsc_devclass;

DRIVER_MODULE(hp, vmbus, pcivsc_driver, pcivsc_devclass, 0, 0);
MODULE_VERSION(hp, 1);
MODULE_DEPEND(hp, vmbus, 1, 1, 1);

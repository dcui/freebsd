# $FreeBSD$

.PATH:  ${.CURDIR}/../../../dev/hyperv/pcivsc \
	${.CURDIR}/../../../dev/hyperv/vmbus

KMOD=	hv_pcivsc
SRCS=	hv_pci_vsc.c
SRCS+=	bus_if.h device_if.h vmbus_if.h

CFLAGS+= -I${.CURDIR}/../../../dev/hyperv/pcivsc

.include <bsd.kmod.mk>

# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0387");
  script_cve_id("CVE-2023-1544", "CVE-2023-3019", "CVE-2023-3255", "CVE-2023-42467", "CVE-2023-5088", "CVE-2023-6683", "CVE-2023-6693", "CVE-2024-24474", "CVE-2024-26327", "CVE-2024-26328", "CVE-2024-3446", "CVE-2024-3447", "CVE-2024-4467", "CVE-2024-7409", "CVE-2024-8354", "CVE-2024-8612");
  script_tag(name:"creation_date", value:"2024-12-05 04:13:16 +0000 (Thu, 05 Dec 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-09 20:15:10 +0000 (Tue, 09 Apr 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0387)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0387");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0387.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33074");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/ES5DXAAMYUC767MUW4BPRP6ZPDL6SUW6/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/HL7L7OSCUZ44UAQCOB6IUOFBWKV6ECP2/");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-April/035064.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-August/036644.html");
  script_xref(name:"URL", value:"https://lwn.net/Articles/971720/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the MGASA-2024-0387 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the QEMU implementation of VMWare's paravirtual RDMA
device. This flaw allows a crafted guest driver to allocate and
initialize a huge number of page tables to be used as a ring of
descriptors for CQ and async events, potentially leading to an
out-of-bounds read and crash of QEMU. (CVE-2023-1544)
A DMA reentrancy issue leading to a use-after-free error was found in
the e1000e NIC emulation code in QEMU. This issue could allow a
privileged guest user to crash the QEMU process on the host, resulting
in a denial of service. (CVE-2023-3019)
A flaw was found in the QEMU built-in VNC server while processing
ClientCutText messages. A wrong exit condition may lead to an infinite
loop when inflating an attacker controlled zlib buffer in the
`inflate_buffer` function. This could allow a remote authenticated
client who is able to send a clipboard to the VNC server to trigger a
denial of service. (CVE-2023-3255)
A bug in QEMU could cause a guest I/O operation otherwise addressed to
an arbitrary disk offset to be targeted to offset 0 instead (potentially
overwriting the VM's boot code). This could be used, for example, by L2
guests with a virtual disk (vdiskL2) stored on a virtual disk of an L1
(vdiskL1) hypervisor to read and/or write data to LBA 0 of vdiskL1,
potentially gaining control of L1 at its next reboot. (CVE-2023-5088)
A flaw was found in the QEMU built-in VNC server while processing
ClientCutText messages. The qemu_clipboard_request() function can be
reached before vnc_server_cut_text_caps() was called and had the chance
to initialize the clipboard peer, leading to a NULL pointer dereference.
This could allow a malicious authenticated VNC client to crash QEMU and
trigger a denial of service. (CVE-2023-6683)
A stack based buffer overflow was found in the virtio-net device of
QEMU. This issue occurs when flushing TX in the virtio_net_flush_tx
function if guest features VIRTIO_NET_F_HASH_REPORT, VIRTIO_F_VERSION_1
and VIRTIO_NET_F_MRG_RXBUF are enabled. This could allow a malicious
user to overwrite local variables allocated on the stack. Specifically,
the `out_sg` variable could be used to read a part of process memory and
send it to the wire, causing an information leak. (CVE-2023-6693)
QEMU through 8.0.0 could trigger a division by zero in scsi_disk_reset
in hw/scsi/scsi-disk.c because scsi_disk_emulate_mode_select does not
prevent s->qdev.blocksize from being 256. This stops QEMU and the guest
immediately. (CVE-2023-42467)
QEMU before 8.2.0 has an integer underflow, and resultant buffer
overflow, via a TI command when an expected non-DMA transfer length is
less than the length of the available FIFO data. This occurs in
esp_do_nodma in hw/scsi/esp.c because of an underflow of async_len.
(CVE-2024-24474)
An issue was discovered in QEMU 7.1.0 through 8.2.1. register_vfs in
hw/pci/pcie_sriov.c mishandles the situation where a guest writes NumVFs
greater ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on Mageia 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-alsa", rpm:"qemu-audio-alsa~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-dbus", rpm:"qemu-audio-dbus~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-jack", rpm:"qemu-audio-jack~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-oss", rpm:"qemu-audio-oss~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-pa", rpm:"qemu-audio-pa~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-sdl", rpm:"qemu-audio-sdl~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-spice", rpm:"qemu-audio-spice~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-dmg", rpm:"qemu-block-dmg~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-iscsi", rpm:"qemu-block-iscsi~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-nfs", rpm:"qemu-block-nfs~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh", rpm:"qemu-block-ssh~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-char-baum", rpm:"qemu-char-baum~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-char-spice", rpm:"qemu-char-spice~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-common", rpm:"qemu-common~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-qxl", rpm:"qemu-device-display-qxl~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-vhost-user-gpu", rpm:"qemu-device-display-vhost-user-gpu~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu", rpm:"qemu-device-display-virtio-gpu~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-ccw", rpm:"qemu-device-display-virtio-gpu-ccw~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-gl", rpm:"qemu-device-display-virtio-gpu-gl~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-pci", rpm:"qemu-device-display-virtio-gpu-pci~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-pci-gl", rpm:"qemu-device-display-virtio-gpu-pci-gl~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-vga", rpm:"qemu-device-display-virtio-vga~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-vga-gl", rpm:"qemu-device-display-virtio-vga-gl~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-usb-host", rpm:"qemu-device-usb-host~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-usb-redirect", rpm:"qemu-device-usb-redirect~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-usb-smartcard", rpm:"qemu-device-usb-smartcard~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-docs", rpm:"qemu-docs~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-core", rpm:"qemu-kvm-core~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-pr-helper", rpm:"qemu-pr-helper~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-aarch64", rpm:"qemu-system-aarch64~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-aarch64-core", rpm:"qemu-system-aarch64-core~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-alpha", rpm:"qemu-system-alpha~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-alpha-core", rpm:"qemu-system-alpha-core~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-arm", rpm:"qemu-system-arm~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-arm-core", rpm:"qemu-system-arm-core~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-avr", rpm:"qemu-system-avr~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-avr-core", rpm:"qemu-system-avr-core~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-cris", rpm:"qemu-system-cris~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-cris-core", rpm:"qemu-system-cris-core~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-hppa", rpm:"qemu-system-hppa~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-hppa-core", rpm:"qemu-system-hppa-core~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-loongarch64", rpm:"qemu-system-loongarch64~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-loongarch64-core", rpm:"qemu-system-loongarch64-core~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-m68k", rpm:"qemu-system-m68k~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-m68k-core", rpm:"qemu-system-m68k-core~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-microblaze", rpm:"qemu-system-microblaze~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-microblaze-core", rpm:"qemu-system-microblaze-core~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-mips", rpm:"qemu-system-mips~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-mips-core", rpm:"qemu-system-mips-core~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-nios2", rpm:"qemu-system-nios2~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-nios2-core", rpm:"qemu-system-nios2-core~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-or1k", rpm:"qemu-system-or1k~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-or1k-core", rpm:"qemu-system-or1k-core~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-ppc", rpm:"qemu-system-ppc~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-ppc-core", rpm:"qemu-system-ppc-core~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-riscv", rpm:"qemu-system-riscv~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-riscv-core", rpm:"qemu-system-riscv-core~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-rx", rpm:"qemu-system-rx~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-rx-core", rpm:"qemu-system-rx-core~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-s390x", rpm:"qemu-system-s390x~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-s390x-core", rpm:"qemu-system-s390x-core~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-sh4", rpm:"qemu-system-sh4~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-sh4-core", rpm:"qemu-system-sh4-core~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-sparc", rpm:"qemu-system-sparc~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-sparc-core", rpm:"qemu-system-sparc-core~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-tricore", rpm:"qemu-system-tricore~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-tricore-core", rpm:"qemu-system-tricore-core~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-x86", rpm:"qemu-system-x86~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-x86-core", rpm:"qemu-system-x86-core~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-xtensa", rpm:"qemu-system-xtensa~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-xtensa-core", rpm:"qemu-system-xtensa-core~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tests", rpm:"qemu-tests~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-curses", rpm:"qemu-ui-curses~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-dbus", rpm:"qemu-ui-dbus~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-egl-headless", rpm:"qemu-ui-egl-headless~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-gtk", rpm:"qemu-ui-gtk~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-opengl", rpm:"qemu-ui-opengl~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-sdl", rpm:"qemu-ui-sdl~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-spice-app", rpm:"qemu-ui-spice-app~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-spice-core", rpm:"qemu-ui-spice-core~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user", rpm:"qemu-user~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-binfmt", rpm:"qemu-user-binfmt~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static", rpm:"qemu-user-static~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-aarch64", rpm:"qemu-user-static-aarch64~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-alpha", rpm:"qemu-user-static-alpha~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-arm", rpm:"qemu-user-static-arm~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-cris", rpm:"qemu-user-static-cris~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-hexagon", rpm:"qemu-user-static-hexagon~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-hppa", rpm:"qemu-user-static-hppa~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-loongarch64", rpm:"qemu-user-static-loongarch64~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-m68k", rpm:"qemu-user-static-m68k~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-microblaze", rpm:"qemu-user-static-microblaze~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-mips", rpm:"qemu-user-static-mips~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-nios2", rpm:"qemu-user-static-nios2~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-or1k", rpm:"qemu-user-static-or1k~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-ppc", rpm:"qemu-user-static-ppc~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-riscv", rpm:"qemu-user-static-riscv~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-s390x", rpm:"qemu-user-static-s390x~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-sh4", rpm:"qemu-user-static-sh4~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-sparc", rpm:"qemu-user-static-sparc~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-x86", rpm:"qemu-user-static-x86~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-xtensa", rpm:"qemu-user-static-xtensa~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-virtiofsd", rpm:"qemu-virtiofsd~7.2.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2879.1");
  script_cve_id("CVE-2016-7161", "CVE-2016-7170", "CVE-2016-7422", "CVE-2016-7466", "CVE-2016-7907", "CVE-2016-7908", "CVE-2016-7909", "CVE-2016-7994", "CVE-2016-7995", "CVE-2016-8576", "CVE-2016-8577", "CVE-2016-8578", "CVE-2016-8667", "CVE-2016-8668", "CVE-2016-8669", "CVE-2016-8909", "CVE-2016-8910", "CVE-2016-9101", "CVE-2016-9104", "CVE-2016-9105", "CVE-2016-9106");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-10-05 17:40:55 +0000 (Wed, 05 Oct 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2879-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2879-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162879-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000345");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1001151");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1002116");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1002549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1002550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1002557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003613");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004707");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006538");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007391");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007493");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007494");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998516");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-November/002411.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the SUSE-SU-2016:2879-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qemu to version 2.6.2 fixes the several issues.

These security issues were fixed:
- CVE-2016-7161: Heap-based buffer overflow in the .receive callback of xlnx.xps-ethernetlite in QEMU (aka Quick Emulator) allowed attackers to execute arbitrary code on the QEMU host via a large ethlite packet (bsc#1001151).
- CVE-2016-7170: OOB stack memory access when processing svga command (bsc#998516).
- CVE-2016-7466: xhci memory leakage during device unplug (bsc#1000345).
- CVE-2016-7422: NULL pointer dereference in virtqueu_map_desc (bsc#1000346).
- CVE-2016-7908: The mcf_fec_do_tx function in hw/net/mcf_fec.c did not properly limit the buffer descriptor count when transmitting packets, which allowed local guest OS administrators to cause a denial of service (infinite loop and QEMU process crash) via vectors involving a buffer descriptor with a length of 0 and crafted values in bd.flags (bsc#1002550).
- CVE-2016-7995: Memory leak in ehci_process_itd (bsc#1003612).
- CVE-2016-8576: The xhci_ring_fetch function in hw/usb/hcd-xhci.c allowed local guest OS administrators to cause a denial of service (infinite loop and QEMU process crash) by leveraging failure to limit the number of link Transfer Request Blocks (TRB) to process (bsc#1003878).
- CVE-2016-8578: The v9fs_iov_vunmarshal function in fsdev/9p-iov-marshal.c allowed local guest OS administrators to cause a denial of service (NULL pointer dereference and QEMU process crash) by sending an empty string parameter to a 9P operation (bsc#1003894).
- CVE-2016-9105: Memory leakage in v9fs_link (bsc#1007494).
- CVE-2016-8577: Memory leak in the v9fs_read function in hw/9pfs/9p.c allowed local guest OS administrators to cause a denial of service (memory consumption) via vectors related to an I/O read operation (bsc#1003893).
- CVE-2016-9106: Memory leakage in v9fs_write (bsc#1007495).
- CVE-2016-8669: The serial_update_parameters function in hw/char/serial.c allowed local guest OS administrators to cause a denial of service (divide-by-zero error and QEMU process crash) via vectors involving a value of divider greater than baud base (bsc#1004707).
- CVE-2016-7909: The pcnet_rdra_addr function in hw/net/pcnet.c allowed local guest OS administrators to cause a denial of service (infinite loop and QEMU process crash) by setting the (1) receive or (2) transmit descriptor ring length to 0 (bsc#1002557).
- CVE-2016-9101: eepro100 memory leakage whern unplugging a device (bsc#1007391).
- CVE-2016-8668: The rocker_io_writel function in hw/net/rocker/rocker.c allowed local guest OS administrators to cause a denial of service (out-of-bounds read and QEMU process crash) by leveraging failure to limit DMA buffer size (bsc#1004706).
- CVE-2016-8910: The rtl8139_cplus_transmit function in hw/net/rtl8139.c allowed local guest OS administrators to cause a denial of service (infinite loop and CPU consumption) by leveraging failure to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.6.2~31.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-arm", rpm:"qemu-arm~2.6.2~31.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~2.6.2~31.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~2.6.2~31.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh", rpm:"qemu-block-ssh~2.6.2~31.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~2.6.2~31.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ipxe", rpm:"qemu-ipxe~1.0.0~31.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.6.2~31.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-lang", rpm:"qemu-lang~2.6.2~31.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ppc", rpm:"qemu-ppc~2.6.2~31.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390", rpm:"qemu-s390~2.6.2~31.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~1.9.1~31.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-sgabios", rpm:"qemu-sgabios~8~31.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~2.6.2~31.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vgabios", rpm:"qemu-vgabios~1.9.1~31.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86", rpm:"qemu-x86~2.6.2~31.2", rls:"SLES12.0SP2"))) {
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

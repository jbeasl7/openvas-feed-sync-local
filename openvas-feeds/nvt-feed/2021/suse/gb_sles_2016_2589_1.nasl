# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2589.1");
  script_cve_id("CVE-2016-2391", "CVE-2016-2392", "CVE-2016-4453", "CVE-2016-4454", "CVE-2016-5105", "CVE-2016-5106", "CVE-2016-5107", "CVE-2016-5126", "CVE-2016-5238", "CVE-2016-5337", "CVE-2016-5338", "CVE-2016-5403", "CVE-2016-6490", "CVE-2016-6833", "CVE-2016-6836", "CVE-2016-6888", "CVE-2016-7116", "CVE-2016-7155", "CVE-2016-7156");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-08-02 18:41:05 +0000 (Tue, 02 Aug 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2589-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2589-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162589-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982019");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982222");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/994760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/994771");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/994774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/996441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997859");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-October/002344.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the SUSE-SU-2016:2589-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"qemu was updated to fix 19 security issues.

These security issues were fixed:
- CVE-2016-2392: The is_rndis function in the USB Net device emulator (hw/usb/dev-network.c) in QEMU did not properly validate USB configuration descriptor objects, which allowed local guest OS administrators to cause a denial of service (NULL pointer dereference and QEMU process crash) via vectors involving a remote NDIS control message packet (bsc#967012)
- CVE-2016-2391: The ohci_bus_start function in the USB OHCI emulation support (hw/usb/hcd-ohci.c) in QEMU allowed local guest OS administrators to cause a denial of service (NULL pointer dereference and QEMU process crash) via vectors related to multiple eof_timers (bsc#967013)
- CVE-2016-5106: The megasas_dcmd_set_properties function in hw/scsi/megasas.c in QEMU, when built with MegaRAID SAS 8708EM2 Host Bus Adapter emulation support, allowed local guest administrators to cause a denial of service (out-of-bounds write access) via vectors involving a MegaRAID Firmware Interface (MFI) command (bsc#982018)
- CVE-2016-5105: The megasas_dcmd_cfg_read function in hw/scsi/megasas.c in QEMU, when built with MegaRAID SAS 8708EM2 Host Bus Adapter emulation support, used an uninitialized variable, which allowed local guest administrators to read host memory via vectors involving a MegaRAID Firmware Interface (MFI) command (bsc#982017)
- CVE-2016-5107: The megasas_lookup_frame function in QEMU, when built with MegaRAID SAS 8708EM2 Host Bus Adapter emulation support, allowed local guest OS administrators to cause a denial of service (out-of-bounds read and crash) via unspecified vectors (bsc#982019)
- CVE-2016-5126: Heap-based buffer overflow in the iscsi_aio_ioctl function in block/iscsi.c in QEMU allowed local guest OS users to cause a denial of service (QEMU process crash) or possibly execute arbitrary code via a crafted iSCSI asynchronous I/O ioctl call (bsc#982285)
- CVE-2016-4454: The vmsvga_fifo_read_raw function in hw/display/vmware_vga.c in QEMU allowed local guest OS administrators to obtain sensitive host memory information or cause a denial of service (QEMU process crash) by changing FIFO registers and issuing a VGA command, which triggers an out-of-bounds read (bsc#982222)
- CVE-2016-4453: The vmsvga_fifo_run function in hw/display/vmware_vga.c in QEMU allowed local guest OS administrators to cause a denial of service (infinite loop and QEMU process crash) via a VGA command (bsc#982223)
- CVE-2016-5338: The (1) esp_reg_read and (2) esp_reg_write functions in hw/scsi/esp.c in QEMU allowed local guest OS administrators to cause a denial of service (QEMU process crash) or execute arbitrary code on the QEMU host via vectors related to the information transfer buffer (bsc#983982)
- CVE-2016-5337: The megasas_ctrl_get_info function in hw/scsi/megasas.c in QEMU allowed local guest OS administrators to obtain sensitive host memory information via ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ipxe", rpm:"qemu-ipxe~1.0.0~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-lang", rpm:"qemu-lang~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ppc", rpm:"qemu-ppc~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390", rpm:"qemu-s390~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~1.8.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-sgabios", rpm:"qemu-sgabios~8~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~2.3.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vgabios", rpm:"qemu-vgabios~1.8.1~21.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86", rpm:"qemu-x86~2.3.1~21.1", rls:"SLES12.0SP1"))) {
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

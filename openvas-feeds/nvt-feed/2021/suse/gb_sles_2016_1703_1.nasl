# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1703.1");
  script_cve_id("CVE-2015-5745", "CVE-2015-7549", "CVE-2015-8504", "CVE-2015-8558", "CVE-2015-8567", "CVE-2015-8568", "CVE-2015-8613", "CVE-2015-8619", "CVE-2015-8743", "CVE-2015-8744", "CVE-2015-8745", "CVE-2015-8817", "CVE-2015-8818", "CVE-2016-1568", "CVE-2016-1714", "CVE-2016-1922", "CVE-2016-1981", "CVE-2016-2197", "CVE-2016-2198", "CVE-2016-2538", "CVE-2016-2841", "CVE-2016-2857", "CVE-2016-2858", "CVE-2016-3710", "CVE-2016-3712", "CVE-2016-4001", "CVE-2016-4002", "CVE-2016-4020", "CVE-2016-4037", "CVE-2016-4439", "CVE-2016-4441", "CVE-2016-4952");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-12 17:44:22 +0000 (Thu, 12 May 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1703-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1703-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161703-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/886378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958491");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959005");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960334");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960835");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961556");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961691");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964411");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969121");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/976109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981266");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-June/002141.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the SUSE-SU-2016:1703-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"qemu was updated to fix 29 security issues.

These security issues were fixed:
- CVE-2016-4439: Avoid OOB access in 53C9X emulation (bsc#980711)
- CVE-2016-4441: Avoid OOB access in 53C9X emulation (bsc#980723)
- CVE-2016-4952: Avoid OOB access in Vmware PV SCSI emulation (bsc#981266)
- CVE-2015-8817: Avoid OOB access in PCI dma I/O (bsc#969121)
- CVE-2015-8818: Avoid OOB access in PCI dma I/O (bsc#969122)
- CVE-2016-3710: Fixed VGA emulation based OOB access with potential for guest escape (bsc#978158)
- CVE-2016-3712: Fixed VGa emulation based DOS and OOB read access exploit (bsc#978160)
- CVE-2016-4037: Fixed USB ehci based DOS (bsc#976109)
- CVE-2016-2538: Fixed potential OOB access in USB net device emulation (bsc#967969)
- CVE-2016-2841: Fixed OOB access / hang in ne2000 emulation (bsc#969350)
- CVE-2016-2858: Avoid potential DOS when using QEMU pseudo random number generator (bsc#970036)
- CVE-2016-2857: Fixed OOB access when processing IP checksums (bsc#970037)
- CVE-2016-4001: Fixed OOB access in Stellaris enet emulated nic (bsc#975128)
- CVE-2016-4002: Fixed OOB access in MIPSnet emulated controller (bsc#975136)
- CVE-2016-4020: Fixed possible host data leakage to guest from TPR access (bsc#975700)
- CVE-2016-2197: Prevent AHCI NULL pointer dereference when using FIS CLB engine (bsc#964411)
- CVE-2015-5745: Buffer overflow in virtio-serial (bsc#940929).
- CVE-2015-7549: PCI null pointer dereferences (bsc#958917).
- CVE-2015-8504: VNC floating point exception (bsc#958491).
- CVE-2015-8558: Infinite loop in ehci_advance_state resulting in DoS (bsc#959005).
- CVE-2015-8567: A guest repeatedly activating a vmxnet3 device can leak host memory (bsc#959386).
- CVE-2015-8568: A guest repeatedly activating a vmxnet3 device can leak host memory (bsc#959386).
- CVE-2015-8613: Wrong sized memset in megasas command handler (bsc#961358).
- CVE-2015-8619: Potential DoS for long HMP sendkey command argument (bsc#960334).
- CVE-2015-8743: OOB memory access in ne2000 ioport r/w functions (bsc#960725).
- CVE-2015-8744: Incorrect l2 header validation could have lead to a crash via assert(2) call (bsc#960835).
- CVE-2015-8745: Reading IMR registers could have lead to a crash via assert(2) call (bsc#960708).
- CVE-2016-1568: AHCI use-after-free in aio port commands (bsc#961332).
- CVE-2016-1714: Potential OOB memory access in processing firmware configuration (bsc#961691).
- CVE-2016-1922: NULL pointer dereference when processing hmp i/o command (bsc#962320).
- CVE-2016-1981: Potential DoS (infinite loop) in e1000 device emulation by malicious privileged user within guest (bsc#963782).
- CVE-2016-2198: Malicious privileged guest user were able to cause DoS by writing to read-only EHCI capabilities registers (bsc#964413).

This non-security issue was fixed
- bsc#886378: qemu truncates vhd images in virt-rescue");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.3.1~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~2.3.1~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~2.3.1~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~2.3.1~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ipxe", rpm:"qemu-ipxe~1.0.0~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.3.1~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-lang", rpm:"qemu-lang~2.3.1~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ppc", rpm:"qemu-ppc~2.3.1~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390", rpm:"qemu-s390~2.3.1~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~1.8.1~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-sgabios", rpm:"qemu-sgabios~8~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~2.3.1~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vgabios", rpm:"qemu-vgabios~1.8.1~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86", rpm:"qemu-x86~2.3.1~14.1", rls:"SLES12.0SP1"))) {
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

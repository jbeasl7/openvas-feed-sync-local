# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1782.1");
  script_cve_id("CVE-2014-7815", "CVE-2015-5154", "CVE-2015-5278", "CVE-2015-5279", "CVE-2015-6855");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-11-09 15:03:53 +0000 (Mon, 09 Nov 2015)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1782-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1782-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151782-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/902737");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928308");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/934506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/934517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936537");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/939216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/943446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945989");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-October/001636.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the SUSE-SU-2015:1782-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"qemu was updated to fix several security issues and bugs.

The following vulnerabilities were fixed:
- CVE-2015-5154: Heap-based buffer overflow in the IDE subsystem in QEMU,
 when the container has a CDROM drive enabled, allows local guest users
 to execute arbitrary code on the host via unspecified ATAPI commands.
 (bsc#938344).
- CVE-2015-5278: QEMU was vulnerable to an infinite loop issue that
 could occur when receiving packets over the network. (bsc#945989)
- CVE-2015-5279: QEMU was vulnerable to a heap buffer overflow issue
 that could occur when receiving packets over the network. (bsc#945987)
- CVE-2015-6855: QEMU was vulnerable to a divide by zero issue that could
 occur while executing an IDE command WIN_READ_NATIVE_MAX to determine
 the maximum size of a drive. (bsc#945404)
- CVE-2014-7815: The set_pixel_format function in ui/vnc.c in QEMU
 allowed remote attackers to cause a denial of service (crash) via a small
 bytes_per_pixel value. (bsc#902737):

Also these non-security issues were fixed:
- bsc#937572: Fixed dictzip on big endian systems
- bsc#934517: Fix 'info tlb' causes guest to freeze
- bsc#934506: Fix vte monitor consol looks empy
- bsc#937125: Fix parsing of scsi-disk wwn uint64 property
- bsc#945778: Drop .probe hooks for DictZip and tar block drivers
- bsc#937572: Fold common-obj-y -> block-obj-y change into original patches
- bsc#928308,bsc#944017: Fix virtio-ccw index errors when initrd gets too large
- bsc#936537: Fix possible qemu-img error when converting to compressed qcow2 image
- bsc#939216: Fix reboot fail after install using uefi
- bsc#943446: qemu-img convert doesn't create MB aligned VHDs anymore");

  script_tag(name:"affected", value:"'qemu' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.0.2~48.9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~2.0.2~48.9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~2.0.2~48.9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~2.0.2~48.9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ipxe", rpm:"qemu-ipxe~1.0.0~48.9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.0.2~48.9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-lang", rpm:"qemu-lang~2.0.2~48.9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ppc", rpm:"qemu-ppc~2.0.2~48.9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390", rpm:"qemu-s390~2.0.2~48.9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~1.7.4~48.9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-sgabios", rpm:"qemu-sgabios~8~48.9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~2.0.2~48.9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vgabios", rpm:"qemu-vgabios~1.7.4~48.9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86", rpm:"qemu-x86~2.0.2~48.9.1", rls:"SLES12.0"))) {
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

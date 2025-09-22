# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123787");
  script_cve_id("CVE-2012-1568", "CVE-2012-2133", "CVE-2012-3400", "CVE-2012-3511");
  script_tag(name:"creation_date", value:"2015-10-06 11:08:33 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2012-1426)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-1426");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-1426.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2012-1426 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-279.14.1.el6]
- [usb] usbhid: Fix use-after-free in USBHID (James Paradis) [864827 857518]
- [usb] Add kernel parameter to force io_watchdog for Intel EHCI HCD (James Paradis) [865713 846024]
- [block] Fix hanging kernel threads in blk_execute_rq() (James Paradis) [865308 855984]
- [mm] hugetlb: do not use vma_hugecache_offset() for vma_prio_tree_foreach (Frederic Weisbecker) [843034 843035] {CVE-2012-2133}
- [mm] hugepages: fix use after free bug in 'quota' handling (Frederic Weisbecker) [843034 843035] {CVE-2012-2133}
- [mm] hugetlb: fix pgoff computation when unmapping page from vma (Frederic Weisbecker) [843034 843035] {CVE-2012-2133}
- [mm] hugetlb: fix ENOSPC returned by handle_mm_fault() (Frederic Weisbecker) [843034 843035] {CVE-2012-2133}
- [fs] gfs2: Write out dirty inode metadata in delayed deletes (Frantisek Hrbata) [859326 748827]
- [usb] core: Fix device removal race condition (James Paradis) [864821 849188]
- [mm] x86_32: fix SHLIB_BASE address typo (Aristeu S. Rozanski F) [804955 804956] {CVE-2012-1568}
- [hid] hidraw: fix window in hidraw_release (Don Zickus) [841824 839973]
- [hid] hidraw: protect hidraw_disconnect() better (Don Zickus) [841824 839973]
- [hid] hidraw: remove excessive _EMERG messages from hidraw (Don Zickus) [841824 839973]
- [hid] hidraw: fix hidraw_disconnect() (Don Zickus) [841824 839973]
- [hid] fix a NULL pointer dereference in hidraw_write (Don Zickus) [841824 839973]
- [hid] fix a NULL pointer dereference in hidraw_ioctl (Don Zickus) [841824 839973]
- [hid] remove BKL from hidraw (Don Zickus) [841824 839973]
- [mm] x86_32: randomize SHLIB_BASE (Aristeu Rozanski) [804955 804956] {CVE-2012-1568}
- [block] fix up use after free in __blkdev_get (Jeff Moyer) [853943 847838]
- [scsi] remove no longer valid BUG_ON in scsi_lld_busy (Jeff Garzik) [860640 842881]
- [scsi] fix NULL request_queue in scsi_requeue_run_queue() (Jeff Garzik) [860640 842881]
- [net] svcrpc: fix BUG() in svc_tcp_clear_pages (J. Bruce Fields) [856106 769045]
- [scsi] lpfc: Fixed SCSI device reset escalation (Rob Evers) [861390 827566]
- [scsi] lpfc: Fix abort status (Rob Evers) [861390 827566]
- [kernel] cgroup: add cgroup_root_mutex (Frederic Weisbecker) [858954 844531]
- [mm] Hold a file reference in madvise_remove (Jerome Marchand) [849738 849739] {CVE-2012-3511}
- [base] driver-core: fix device_register race (Rob Evers) [860784 833098]
- [netdrv] e1000e: drop check of RXCW.CW to eliminate link going up and down (Dean Nelson) [857055 847310]
- [scsi] be2iscsi: Format the MAC_ADDR with sysfs (Rob Evers) [863147 827594]
- [usb] usbdevfs: Add a USBDEVFS_GET_CAPABILITIES ioctl (Don Zickus) [841667 828271]
- [fs] udf: fix return value on error path in udf_load_logicalvol (Nikola Pajkovsky) [843142 843143] {CVE-2012-3400}
- [fs] udf: Improve table length check to avoid possible overflow (Nikola Pajkovsky) [843142 843143] {CVE-2012-3400}
- [fs] udf: Fortify ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~279.14.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~279.14.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~279.14.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~279.14.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~279.14.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~279.14.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~279.14.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~279.14.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~279.14.1.el6", rls:"OracleLinux6"))) {
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

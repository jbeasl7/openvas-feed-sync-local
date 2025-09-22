# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123575");
  script_cve_id("CVE-2012-6549", "CVE-2013-1772", "CVE-2013-2140", "CVE-2013-2164", "CVE-2013-2234", "CVE-2013-3076", "CVE-2013-4163");
  script_tag(name:"creation_date", value:"2015-10-06 11:05:44 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");

  script_name("Oracle: Security Advisory (ELSA-2013-2546)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-2546");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-2546.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-uek' package(s) announced via the ELSA-2013-2546 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.39-400.209.1]
- Revert 'stop mig handler when lockres in progress ,and return -EAGAIN' (Srinivas Eeda) [Orabug: 16924802]
- ocfs2/dlm: Fix list traversal in dlm_process_recovery_data (Srinivas Eeda) [Orabug: 17432400]
- ocfs2/dlm: ocfs2 dlm umount skip migrating lockres (Srinivas Eeda) [Orabug: 16859627]

[2.6.39-400.208.1]
- Btrfs: make the chunk allocator completely tree lockless (Josef Bacik) [Orabug: 17334251]
- mpt2sas: protect mpt2sas_ioc_list access with lock (Jerry Snitselaar) [Orabug: 17383579]
- mptsas: update to 4.28.20.02 (Jerry Snitselaar) [Orabug: 17294806]
- RDS: protocol negotiation fails during reconnect (Bang Nguyen) [Orabug: 17375389]
- config:remove LM80 modules to void blindly loading cause crash (ethan.zhao) [Orabug: 16976462]

[2.6.39-400.207.0]
- Update lpfc version for 8.3.7.26.3p driver release (Gairy Grannum) [Orabug: 17340816]
- lpfc 8.3.36: Update DIF support for passthru/strip/insert (James Smart) [Orabug: 17340816]
- Update lpfc version for 8.3.7.26.1p driver release (Gairy Grannum) [Orabug: 17376967]
- lpfc: whitespace fix (Vaios Papadimitriou) [Orabug: 17376967]
- Update copyrights for 8.3.41 modifications (James Smart) [Orabug: 17376967]
- Add first burst support to driver (James Smart) [Orabug: 17376967]
- Fixed the format of some log message fields (James Smart) [Orabug: 17376967]
- Add first burst support to driver (James Smart) [Orabug: 17376967]
- Fixed not able to perform PCI function reset when board was not in online mode (James Smart) [Orabug: 17376967]
- Fixed failure in setting SLI3 board mode (James Smart) [Orabug: 17376967]
- Fixed SLI3 failing FCP write on check-condition no-sense with residual zero (James Smart) [Orabug: 17376967]
- Fixed support for 128 byte WQEs (James Smart) [Orabug: 17376967]
- Ensure driver properly zeros unused fields in SLI4 mailbox commands (James Smart) [Orabug: 17376967]
- Fixed max value of lpfc_lun_queue_depth (James Smart) [Orabug: 17376967]
- Fixed Receive Queue varied frame size handling (James Smart) [Orabug: 17376967]
- Fix mailbox byteswap issue on PPC (James Smart) [Orabug: 17376967]
- lpfc 8.3.40: Update Copyrights to 2013 for 8.3.38, 8.3.39, and 8.3.40 modifications (James Smart) [Orabug: 17376967]
- Fixed freeing of iocb when internal loopback times out (James Smart) [Orabug: 17376967]
- lpfc 8.3.40: Fixed a race condition between SLI host and port failed FCF rediscovery (James Smart) [Orabug: 17376967]
- lpfc 8.3.40: Fixed issue mailbox wait routine failed to issue dump memory mbox command (James Smart) [Orabug: 17376967]
- treewide: Fix typos in kernel messages (Masanari Iida) [Orabug: 17376967]
- lpfc 8.3.40: Fixed system panic due to unsafe walking and deleting linked list (James Smart) [Orabug: 17376967]
- lpfc 8.3.40: Fixed FCoE connection list vlan identifier and add FCF list debug (James Smart) [Orabug: 17376967]
- lpfc 8.3.40: Clarified the behavior of the lpfc_max_luns ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-uek' package(s) on Oracle Linux 5, Oracle Linux 6.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.209.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.209.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.209.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.209.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.209.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.209.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.209.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.209.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.209.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.209.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.209.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.209.1.el6uek", rls:"OracleLinux6"))) {
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

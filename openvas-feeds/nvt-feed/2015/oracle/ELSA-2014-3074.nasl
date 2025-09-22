# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123315");
  script_cve_id("CVE-2014-3917");
  script_tag(name:"creation_date", value:"2015-10-06 11:02:10 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2014-3074)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-3074");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-3074.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-uek' package(s) announced via the ELSA-2014-3074 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.39-400.215.10]
- auditsc: audit_krule mask accesses need bounds checking (Andy Lutomirski) [Orabug: 19590597] {CVE-2014-3917}

[2.6.39-400.215.9]
- oracleasm: Add support for new error return codes from block/SCSI (Martin K. Petersen) [Orabug: 18438934]

[2.6.39-400.215.8]
- ib_ipoib: CSUM support in connected mode (Yuval Shaia) [Orabug: 18692878]
- net: Reduce high cpu usage in bonding driver by do_csum (Venkat Venkatsubra) [Orabug: 18141731]
- [random] Partially revert 6d7c7e49: random: make 'add_interrupt_randomness() (John Sobecki) [Orabug: 17740293]
- oracleasm: claim FMODE_EXCL access on disk during asm_open (Srinivas Eeda) [Orabug: 19453460]
- notify block layer when using temporary change to cache_type (Vaughan Cao) [Orabug: 19448451]
- sd: Fix parsing of 'temporary ' cache mode prefix (Ben Hutchings) [Orabug: 19448451]
- sd: fix array cache flushing bug causing performance problems (James Bottomley) [Orabug: 19448451]
- block: fix max discard sectors limit (James Bottomley) [Orabug: 18961244]
- xen-netback: fix deadlock in high memory pressure (Junxiao Bi) [Orabug: 18959416]
- sdp: fix keepalive functionality (shamir rabinovitch) [Orabug: 18728784]
- SELinux: Fix possible NULL pointer dereference in selinux_inode_permission() (Steven Rostedt) [Orabug: 18552029]
- refcount: take rw_lock in ocfs2_reflink (Wengang Wang) [Orabug: 18406219]
- ipv6: check return value for dst_alloc (Madalin Bucur) [Orabug: 17865160]
- cciss: bug fix to prevent cciss from loading in kdump crash kernel (Mike Miller) [Orabug: 17740446]
- configfs: fix race between dentry put and lookup (Junxiao Bi) [Orabug: 17627075]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.215.10.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.215.10.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.215.10.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.215.10.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.215.10.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.215.10.el5uek", rls:"OracleLinux5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.215.10.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.215.10.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.215.10.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.215.10.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.215.10.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.215.10.el6uek", rls:"OracleLinux6"))) {
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

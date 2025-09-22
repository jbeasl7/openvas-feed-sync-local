# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123907");
  script_cve_id("CVE-2012-0217", "CVE-2012-2934");
  script_tag(name:"creation_date", value:"2015-10-06 11:10:08 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2012-0721)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0721");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0721.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-308.8.2.el5, oracleasm-2.6.18-308.8.2.el5' package(s) announced via the ELSA-2012-0721 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel:

[2.6.18-308.8.2.el5]
- [xen] x86_64: check address on trap handlers or guest callbacks (Paolo Bonzini) [813430 813431] {CVE-2012-0217}
- [xen] x86_64: Do not execute sysret with a non-canonical return address (Paolo Bonzini) [813430 813431] {CVE-2012-0217}
- [xen] x86: prevent hv boot on AMD CPUs with Erratum 121 (Laszlo Ersek) [824969 824970]

ocfs2:

[1.4.10]
- ocfs2/dlm: Cleanup mlogs in dlmthread.c dlmast.c and dlmdomain.c
- ocfs2/dlm: make existing conversion precedent over new lock
- ocfs2/dlm: Cleanup dlmdebug.c
- ocfs2/dlm: Minor cleanup
- ocfs2/dlm: Hard code the values for enums
- ocfs2: Wakeup down convert thread just after clearing OCFS2 LOCK UPCONVERT FINISHING
- ocfs2/dlm: Take inflight reference count for remotely mastered resources too
- ocfs2/dlm: dlmlock remote needs to account for remastery
- ocfs2: Add some trace log for orphan scan
- ocfs2: Remove unused old id in ocfs2_commit_cache
- ocfs2: Remove obsolete comments before ocfs2_start_trans
- ocfs2: Initialize the bktcnt variable properly and call it bucket_count
- ocfs2: Use cpu to le16 for e leaf clusters in ocfs2_bg_discontig_add_extent
- ocfs2: validate bg free bits count after update
- ocfs2: cluster Pin the remote node item in configfs
- ocfs2: Release buffer head in case of error in ocfs2_double_lock
- ocfs2: optimize ocfs2 check dir entry with unlikely() annotations
- ocfs2: Little refactoring against ocfs2 iget
- ocfs2: Initialize data ac might be used uninitializ
- ocfs2 Skip mount recovery for hard ro mounts
- ocfs2: make direntry invalid when deleting it
- ocfs2: commit trans in error
- ocfs2: Fix deadlock when allocating page
- ocfs2: Avoid livelock in ocfs2 readpage");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-308.8.2.el5, oracleasm-2.6.18-308.8.2.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~308.8.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~308.8.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~308.8.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~308.8.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~308.8.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~308.8.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~308.8.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~308.8.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~308.8.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~308.8.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.8.2.el5", rpm:"ocfs2-2.6.18-308.8.2.el5~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.8.2.el5PAE", rpm:"ocfs2-2.6.18-308.8.2.el5PAE~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.8.2.el5debug", rpm:"ocfs2-2.6.18-308.8.2.el5debug~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.8.2.el5xen", rpm:"ocfs2-2.6.18-308.8.2.el5xen~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.8.2.el5", rpm:"oracleasm-2.6.18-308.8.2.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.8.2.el5PAE", rpm:"oracleasm-2.6.18-308.8.2.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.8.2.el5debug", rpm:"oracleasm-2.6.18-308.8.2.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.8.2.el5xen", rpm:"oracleasm-2.6.18-308.8.2.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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

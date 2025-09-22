# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122649");
  script_cve_id("CVE-2007-3105", "CVE-2007-3380", "CVE-2007-3513", "CVE-2007-3731", "CVE-2007-3848", "CVE-2007-3850", "CVE-2007-4133", "CVE-2007-4308", "CVE-2007-4574");
  script_tag(name:"creation_date", value:"2015-10-08 11:50:15 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2007-0940)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2007-0940");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2007-0940.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-8.1.15.0.1.el5, oracleasm-2.6.18-8.1.15.0.1.el5' package(s) announced via the ELSA-2007-0940 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-8.1.15.0.1.el5]
 - Fix bonding primary=ethX (Bert Barbe) [IT 101532] [ORA 5136660]
 - Add entropy module option to e1000/bnx2 (John Sobecki) [ORA 6045759]

 [2.6.18-8.1.15.el5]
 - [dlm] A TCP connection to DLM port blocks DLM operations (Patrick
 Caulfield ) [245922] {CVE-2007-3380}
 - [ppc] 4k page mapping support for userspace in 64k kernels (Scott
 Moser ) [275841] {CVE-2007-3850}
 - [ptrace] NULL pointer dereference triggered by ptrace (Anton Arapov )
 [275981] {CVE-2007-3731}
 - [fs] hugetlb: fix prio_tree unit (Konrad Rzeszutek ) [253929]
 {CVE-2007-4133}
 - [x86_64] Don't leak NT bit into next task (Dave Anderson ) [298151]
 {CVE-2007-4574}
 - [fs] Reset current->pdeath_signal on SUID binary execution (Peter
 Zijlstra ) [252307] {CVE-2007-3848}
 - [misc] Bounds check ordering issue in random driver (Anton Arapov )
 [275961] {CVE-2007-3105}
 - [usb] usblcd: Locally triggerable memory consumption (Anton Arapov )
 [276001] {CVE-2007-3513}
 - [net] igmp: check for NULL when allocating GFP_ATOMIC skbs (Neil
 Horman ) [303281]
 - [scsi] aacraid: Missing ioctl() permission checks (Vitaly Mayatskikh )
 [298371] {CVE-2007-4308}
 - [xen] Guest access to MSR may cause system crash/data corruption
 (Bhavana Nagendra ) [253312] {CVE-2007-3733}");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-8.1.15.0.1.el5, oracleasm-2.6.18-8.1.15.0.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~8.1.15.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~8.1.15.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~8.1.15.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~8.1.15.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~8.1.15.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~8.1.15.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~8.1.15.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~8.1.15.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-8.1.15.0.1.el5", rpm:"ocfs2-2.6.18-8.1.15.0.1.el5~1.2.6~6.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-8.1.15.0.1.el5PAE", rpm:"ocfs2-2.6.18-8.1.15.0.1.el5PAE~1.2.6~6.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-8.1.15.0.1.el5xen", rpm:"ocfs2-2.6.18-8.1.15.0.1.el5xen~1.2.6~6.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-8.1.15.0.1.el5", rpm:"oracleasm-2.6.18-8.1.15.0.1.el5~2.0.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-8.1.15.0.1.el5PAE", rpm:"oracleasm-2.6.18-8.1.15.0.1.el5PAE~2.0.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-8.1.15.0.1.el5xen", rpm:"oracleasm-2.6.18-8.1.15.0.1.el5xen~2.0.4~1.el5", rls:"OracleLinux5"))) {
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

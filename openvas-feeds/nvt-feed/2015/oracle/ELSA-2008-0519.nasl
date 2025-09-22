# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122573");
  script_cve_id("CVE-2008-0598", "CVE-2008-2358", "CVE-2008-2729");
  script_tag(name:"creation_date", value:"2015-10-08 11:48:24 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2008-0519)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2008-0519");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2008-0519.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-92.1.6.0.2.el5, oracleasm-2.6.18-92.1.6.0.2.el5' package(s) announced via the ELSA-2008-0519 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-92.1.6.0.2.el5]
- [NET] Add entropy support to e1000 and bnx2 (John Sobecki) [orabug 6045759]
- [splice] Fix bad unlock_page() in error case (Jens Axboe) [orabug 6263574]
- [dio] fix error-path crashes (Linus Torvalds) [orabug 6242289]
- [NET] fix netpoll race (Tina Yang) [orabugz 5791]

[2.6.18-92.1.6.el5]
- [x86] sanity checking for read_tsc on i386 (Brian Maly ) [447686 443435]

[2.6.18-92.1.5.el5]
- [x86_64] copy_user doesn't zero tail bytes on page fault (Vitaly Mayatskikh) [451275 451276] {CVE-2008-2729}

[2.6.18-92.1.4.el5]
- Revert: [misc] ttyS1 loses interrupt and stops transmitting (Simon McGrath ) [443071 440121]

[2.6.18-92.1.3.el5]
- [x86_64] fix possible data leaks in copy_from_user() routine (Anton Arapov ) [433944 433945] {CVE-2008-0598}

[2.6.18-92.1.2.el5]
- [misc] ttyS1 loses interrupt and stops transmitting (Simon McGrath ) [443071 440121]
- [net] DCCP sanity check feature length (Anton Arapov ) [447395 447396] {CVE-2008-2358}
- [misc] fix possible buffer overflow in ASN.1 parsing routine (Anton Arapov ) [444464 444465] {CVE-2008-1673}");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-92.1.6.0.2.el5, oracleasm-2.6.18-92.1.6.0.2.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~92.1.6.0.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~92.1.6.0.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~92.1.6.0.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~92.1.6.0.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~92.1.6.0.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~92.1.6.0.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~92.1.6.0.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~92.1.6.0.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~92.1.6.0.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~92.1.6.0.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-92.1.6.0.2.el5", rpm:"ocfs2-2.6.18-92.1.6.0.2.el5~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-92.1.6.0.2.el5PAE", rpm:"ocfs2-2.6.18-92.1.6.0.2.el5PAE~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-92.1.6.0.2.el5debug", rpm:"ocfs2-2.6.18-92.1.6.0.2.el5debug~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-92.1.6.0.2.el5xen", rpm:"ocfs2-2.6.18-92.1.6.0.2.el5xen~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-92.1.6.0.2.el5", rpm:"oracleasm-2.6.18-92.1.6.0.2.el5~2.0.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-92.1.6.0.2.el5PAE", rpm:"oracleasm-2.6.18-92.1.6.0.2.el5PAE~2.0.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-92.1.6.0.2.el5debug", rpm:"oracleasm-2.6.18-92.1.6.0.2.el5debug~2.0.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-92.1.6.0.2.el5xen", rpm:"oracleasm-2.6.18-92.1.6.0.2.el5xen~2.0.4~1.el5", rls:"OracleLinux5"))) {
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

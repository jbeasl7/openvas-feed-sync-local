# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122516");
  script_cve_id("CVE-2008-4933", "CVE-2008-4934", "CVE-2008-5025", "CVE-2008-5713", "CVE-2009-0031", "CVE-2009-0065");
  script_tag(name:"creation_date", value:"2015-10-08 11:47:08 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2009-0264)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2009-0264");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2009-0264.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-128.1.1.0.1.el5, oracleasm-2.6.18-128.1.1.0.1.el5' package(s) announced via the ELSA-2009-0264 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-128.1.1.0.1.el5]
- [NET] Add entropy support to e1000 and bnx2 (John Sobecki,Guru Anbalagane) [orabug 6045759]
- [MM] shrink zone patch (John Sobecki,Chris Mason) [orabug 6086839]
- [NET] Add xen pv/bonding netconsole support (Tina yang) [orabug 6993043] [bz 7258]
- [nfs] convert ENETUNREACH to ENOTCONN (Guru Anbalagane) [orabug 7689332]

[2.6.18-128.1.1.el5]
- [security] introduce missing kfree (Jiri Pirko ) [480597 480598] {CVE-2009-0031}
- [sched] fix clock_gettime monotonicity (Peter Zijlstra ) [481122 477763]
- [nfs] create rpc clients with proper auth flavor (Jeff Layton ) [481119 465456]
- [net] sctp: overflow with bad stream ID in FWD-TSN chunk (Eugene Teo ) [478804 478805] {CVE-2009-0065}
- [md] fix oops with device-mapper mirror target (Heinz Mauelshagen ) [481120 472558]
- [openib] restore traffic in connected mode on HCA (AMEET M. PARANJAPE ) [479812 477000]
- [net] add preemption point in qdisc_run (Jiri Pirko ) [477746 471398] {CVE-2008-5713}
- [x86_64] copy_user_c assembler can leave garbage in rsi (Larry Woodman ) [481117 456682]
- [misc] setpgid returns ESRCH in some situations (Oleg Nesterov ) [480576 472433]
- [s390] zfcp: fix hexdump data in s390dbf traces (Hans-Joachim Picht ) [480996 470618]
- [fs] hfsplus: fix buffer overflow with a corrupted image (Anton Arapov ) [469637 469638] {CVE-2008-4933}
- [fs] hfsplus: check read_mapping_page return value (Anton Arapov ) [469644 469645] {CVE-2008-4934}
- [fs] hfs: fix namelength memory corruption (Anton Arapov ) [470772 470773] {CVE-2008-5025}");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-128.1.1.0.1.el5, oracleasm-2.6.18-128.1.1.0.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~128.1.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~128.1.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~128.1.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~128.1.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~128.1.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~128.1.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~128.1.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~128.1.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~128.1.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~128.1.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-128.1.1.0.1.el5", rpm:"ocfs2-2.6.18-128.1.1.0.1.el5~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-128.1.1.0.1.el5PAE", rpm:"ocfs2-2.6.18-128.1.1.0.1.el5PAE~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-128.1.1.0.1.el5debug", rpm:"ocfs2-2.6.18-128.1.1.0.1.el5debug~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-128.1.1.0.1.el5xen", rpm:"ocfs2-2.6.18-128.1.1.0.1.el5xen~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-128.1.1.0.1.el5", rpm:"oracleasm-2.6.18-128.1.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-128.1.1.0.1.el5PAE", rpm:"oracleasm-2.6.18-128.1.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-128.1.1.0.1.el5debug", rpm:"oracleasm-2.6.18-128.1.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-128.1.1.0.1.el5xen", rpm:"oracleasm-2.6.18-128.1.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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

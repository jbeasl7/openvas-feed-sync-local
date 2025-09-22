# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122564");
  script_cve_id("CVE-2008-1294", "CVE-2008-2136", "CVE-2008-2812");
  script_tag(name:"creation_date", value:"2015-10-08 11:48:03 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 15:35:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2008-0612)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2008-0612");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2008-0612.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-92.1.10.0.1.el5, oracleasm-2.6.18-92.1.10.0.1.el5' package(s) announced via the ELSA-2008-0612 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-92.1.10.0.1.el5]
- [NET] Add entropy support to e1000 and bnx2 (John Sobecki) [orabug 6045759]
- [splice] Fix bad unlock_page() in error case (Jens Axboe) [orabug 6263574]
- [dio] fix error-path crashes (Linus Torvalds) [orabug 6242289]
- [NET] fix netpoll race (Tina Yang) [orabugz 5791]

[2.6.18-92.1.10.el5]
- [ia64] softlock: prevent endless warnings in kdump (Neil Horman ) [456117 453200]

[2.6.18-92.1.9.el5]
- [misc] signaling msgrvc() should not pass back error (Jiri Pirko ) [455278 452533]
- [ia64] properly unregister legacy interrupts (Prarit Bhargava ) [450337 445886]

[2.6.18-92.1.8.el5]
- [net] randomize udp port allocation (Eugene Teo ) [454571 454572]
- [tty] add NULL pointer checks (Aristeu Rozanski ) [453425 453154] {CVE-2008-2812}
- [net] sctp: make sure sctp_addr does not overflow (David S. Miller ) [452482 452483] {CVE-2008-2826}
- [sys] sys_setrlimit: prevent setting RLIMIT_CPU to 0 (Neil Horman ) [437121 437122] {CVE-2008-1294}
- [net] sit: exploitable remote memory leak (Jiri Pirko ) [446038 446039] {CVE-2008-2136}
- [misc] ttyS1 lost interrupt, stops transmitting v2 (Brian Maly ) [455256 451157]
- [misc] ttyS1 loses interrupt and stops transmitting (Simon McGrath ) [443071 440121]

[2.6.18-92.1.7.el5]
- [x86_64]: extend MCE banks support for Dunnington, Nehalem (Prarit Bhargava ) [451941 446673]
- [nfs] address nfs rewrite performance regression in RHEL5 (Eric Sandeen ) [448685 436004]
- [mm] Make mmap() with PROT_WRITE on RHEL5 (Larry Woodman ) [450758 448978]
- [i386]: Add check for supported_cpus in powernow_k8 driver (Prarit Bhargava ) [450866 443853]
- [i386]: Add check for dmi_data in powernow_k8 driver (Prarit Bhargava ) [450866 443853]
- [net] fix recv return zero (Thomas Graf ) [452231 435657]
- [misc] kernel crashes on futex (Anton Arapov ) [450336 435178]
- [net] Fixing bonding rtnl_lock screwups (Fabio Olive Leite ) [451939 450219]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-92.1.10.0.1.el5, oracleasm-2.6.18-92.1.10.0.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~92.1.10.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~92.1.10.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~92.1.10.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~92.1.10.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~92.1.10.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~92.1.10.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~92.1.10.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~92.1.10.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~92.1.10.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~92.1.10.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-92.1.10.0.1.el5", rpm:"ocfs2-2.6.18-92.1.10.0.1.el5~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-92.1.10.0.1.el5PAE", rpm:"ocfs2-2.6.18-92.1.10.0.1.el5PAE~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-92.1.10.0.1.el5debug", rpm:"ocfs2-2.6.18-92.1.10.0.1.el5debug~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-92.1.10.0.1.el5xen", rpm:"ocfs2-2.6.18-92.1.10.0.1.el5xen~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-92.1.10.0.1.el5", rpm:"oracleasm-2.6.18-92.1.10.0.1.el5~2.0.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-92.1.10.0.1.el5PAE", rpm:"oracleasm-2.6.18-92.1.10.0.1.el5PAE~2.0.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-92.1.10.0.1.el5debug", rpm:"oracleasm-2.6.18-92.1.10.0.1.el5debug~2.0.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-92.1.10.0.1.el5xen", rpm:"oracleasm-2.6.18-92.1.10.0.1.el5xen~2.0.4~1.el5", rls:"OracleLinux5"))) {
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

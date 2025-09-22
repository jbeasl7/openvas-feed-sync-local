# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122589");
  script_cve_id("CVE-2007-5093", "CVE-2007-6282", "CVE-2007-6712", "CVE-2008-1615");
  script_tag(name:"creation_date", value:"2015-10-08 11:48:43 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2008-0275)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2008-0275");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2008-0275.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-53.1.21.0.1.el5, oracleasm-2.6.18-53.1.21.0.1.el5' package(s) announced via the ELSA-2008-0275 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-53.1.21.0.1.el5]
- [NET] Add entropy support to e1000 and bnx2 (John Sobecki) [ORA 6045759]
- [NET] Fix msi issue with kexec/kdump (Michael Chan) [ORA 6219364]
- [MM] Fix alloc_pages_node() static 'nid' race made kernel crash (Joe Jin) [ORA 6187457]
- [splice] Fix bad unlock_page() in error case (Jens Axboe) [ORA 6263574]
- [dio] fix error-path crashes (Linux Torvalds) [ORA 6242289]

[2.6.18-53.1.21.el5]
- [misc] infinite loop in highres timers (Michal Schmidt ) [440001]
- [video] PWC driver DoS (Pete Zaitcev ) [308521]
- [x86_64] fix unprivileged crash on %cs corruption (Jarod Wilson ) [439787]
- [net] ESP: ensure IV is in linear part of the skb (Thomas Graf ) [427247]
- [cpufreq] booting with maxcpus=1 panics (Doug Chapman ) [429516]
- [net] sunrpc: lockd recovery is broken (Steve Dickson ) [445360]
- [cpufreq] don't take sem in cpufreq_quick_get (Doug Chapman ) [400821]
- [cpufreq] remove hotplug cpu cruft (Doug Chapman ) [400821]
- [cpufreq] governor: use new rwsem locking in work cb (Doug Chapman ) [400821]
- [cpufreq] ondemand governor restructure the work cb (Doug Chapman ) [400821]
- [cpufreq] rewrite lock to eliminate hotplug issues (Doug Chapman ) [400821]

[2.6.18-53.1.20.el5]
- [misc] fix softlockup warnings/crashes (Chris Lalancette ) [444402]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-53.1.21.0.1.el5, oracleasm-2.6.18-53.1.21.0.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~53.1.21.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~53.1.21.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~53.1.21.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~53.1.21.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~53.1.21.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~53.1.21.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~53.1.21.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~53.1.21.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~53.1.21.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~53.1.21.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-53.1.21.0.1.el5", rpm:"ocfs2-2.6.18-53.1.21.0.1.el5~1.2.8~2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-53.1.21.0.1.el5PAE", rpm:"ocfs2-2.6.18-53.1.21.0.1.el5PAE~1.2.8~2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-53.1.21.0.1.el5debug", rpm:"ocfs2-2.6.18-53.1.21.0.1.el5debug~1.2.8~2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-53.1.21.0.1.el5xen", rpm:"ocfs2-2.6.18-53.1.21.0.1.el5xen~1.2.8~2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-53.1.21.0.1.el5", rpm:"oracleasm-2.6.18-53.1.21.0.1.el5~2.0.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-53.1.21.0.1.el5PAE", rpm:"oracleasm-2.6.18-53.1.21.0.1.el5PAE~2.0.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-53.1.21.0.1.el5debug", rpm:"oracleasm-2.6.18-53.1.21.0.1.el5debug~2.0.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-53.1.21.0.1.el5xen", rpm:"oracleasm-2.6.18-53.1.21.0.1.el5xen~2.0.4~1.el5", rls:"OracleLinux5"))) {
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

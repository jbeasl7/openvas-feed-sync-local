# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123583");
  script_cve_id("CVE-2013-2147", "CVE-2013-2164", "CVE-2013-2206", "CVE-2013-2224", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2237");
  script_tag(name:"creation_date", value:"2015-10-06 11:05:51 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-1166)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1166");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1166.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-348.16.1.el5, oracleasm-2.6.18-348.16.1.el5' package(s) announced via the ELSA-2013-1166 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel
[2.6.18-348.16.1]
- [x86_64] Fix kdump failure due to 'x86_64: Early segment setup' (Paolo Bonzini) [988251 987244]
- [xen] skip tracing if it was disabled instead of dying (Igor Mammedov) [987976 967053]
- [ia64] fix KABI breakage on ia64 (Prarit Bhargava) [966878 960783]
- [x86] fpu: fix CONFIG_PREEMPT=y corruption of FPU stack (Prarit Bhargava) [948187 731531]
- [i386] add sleazy FPU optimization (Prarit Bhargava) [948187 731531]
- [x86-64] non lazy 'sleazy' fpu implementation (Prarit Bhargava) [948187 731531]

[2.6.18-348.15.1]
- [fs] nfs: flush cached dir information slightly more readily (Scott Mayhew) [976441 853145]
- [fs] nfs: Fix resolution prob with cache_change_attribute (Scott Mayhew) [976441 853145]
- [fs] nfs: define function to update nfsi->cache_change_attribute (Scott Mayhew) [976441 853145]
- [net] af_key: fix info leaks in notify messages (Jiri Benc) [980999 981000] {CVE-2013-2234}
- [net] af_key: initialize satype in key_notify_policy_flush() (Jiri Benc) [981222 981224] {CVE-2013-2237}
- [net] ipv6: ip6_sk_dst_check() must not assume ipv6 dst (Jiri Pirko) [981556 981557] {CVE-2013-2232}
- [net] fix invalid free in ip_cmsg_send() callers (Petr Matousek) [980141 980142] {CVE-2013-2224}
- [x86_64] Early segment setup for VT (Paolo Bonzini) [979920 978305]
- [block] cpqarray: info leak in ida_locked_ioctl() (Tomas Henzl) [971245 971246] {CVE-2013-2147}
- [block] cdrom: use kzalloc() for failing hardware (Frantisek Hrbata) [973103 973104] {CVE-2013-2164}
- [mm] Break out when there is nothing more to write for the fs. (Larry Woodman) [972583 965359]

[2.6.18-348.14.1]
- [net] Fix panic for vlan over gre via tun (Thomas Graf) [983452 981337]
- [x86] mm: introduce proper mem barriers smp_invalidate_interrupt (Rafael Aquini) [983628 865095]

[2.6.18-348.13.1]
- [net] sctp: Disallow new connection on a closing socket (Daniel Borkmann) [976569 974936] {CVE-2013-2206}
- [net] sctp: Use correct sideffect command in dup cookie handling (Daniel Borkmann) [976569 974936] {CVE-2013-2206}
- [net] sctp: deal with multiple COOKIE_ECHO chunks (Daniel Borkmann) [976569 974936] {CVE-2013-2206}
- [net] tcp: bind() use stronger condition for bind_conflict (Flavio Leitner) [980811 957604]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-348.16.1.el5, oracleasm-2.6.18-348.16.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~348.16.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~348.16.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~348.16.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~348.16.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~348.16.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~348.16.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~348.16.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~348.16.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~348.16.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~348.16.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-348.16.1.el5", rpm:"ocfs2-2.6.18-348.16.1.el5~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-348.16.1.el5PAE", rpm:"ocfs2-2.6.18-348.16.1.el5PAE~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-348.16.1.el5debug", rpm:"ocfs2-2.6.18-348.16.1.el5debug~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-348.16.1.el5xen", rpm:"ocfs2-2.6.18-348.16.1.el5xen~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-348.16.1.el5", rpm:"oracleasm-2.6.18-348.16.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-348.16.1.el5PAE", rpm:"oracleasm-2.6.18-348.16.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-348.16.1.el5debug", rpm:"oracleasm-2.6.18-348.16.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-348.16.1.el5xen", rpm:"oracleasm-2.6.18-348.16.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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

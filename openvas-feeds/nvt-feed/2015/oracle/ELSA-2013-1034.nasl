# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123600");
  script_cve_id("CVE-2012-6544", "CVE-2012-6545", "CVE-2013-0914", "CVE-2013-1929", "CVE-2013-3222", "CVE-2013-3224", "CVE-2013-3231", "CVE-2013-3235");
  script_tag(name:"creation_date", value:"2015-10-06 11:06:05 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");

  script_name("Oracle: Security Advisory (ELSA-2013-1034)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1034");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1034.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-348.12.1.el5, oracleasm-2.6.18-348.12.1.el5' package(s) announced via the ELSA-2013-1034 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel
[2.6.18-348.12.1]
- Revert: [fs] afs: export a couple of core functions for AFS write support (Lukas Czerner) [960014 692071]
- Revert: [fs] ext4: drop ec_type from the ext4_ext_cache structure (Lukas Czerner) [960014 692071]
- Revert: [fs] ext4: handle NULL p_ext in ext4_ext_next_allocated_block() (Lukas Czerner) [960014 692071]
- Revert: [fs] ext4: make FIEMAP and delayed allocation play well together (Lukas Czerner) [960014 692071]
- Revert: [fs] ext4: Fix possibly very long loop in fiemap (Lukas Czerner) [960014 692071]
- Revert: [fs] ext4: prevent race while walking extent tree for fiemap (Lukas Czerner) [960014 692071]

[2.6.18-348.11.1]
- Revert: [kernel] kmod: make request_module() killable (Frantisek Hrbata) [858752 858753] {CVE-2012-4398}
- Revert: [kernel] kmod: avoid deadlock from recursive kmod call (Frantisek Hrbata) [858752 858753] {CVE-2012-4398}
- Revert: [kernel] wait_for_helper: remove unneeded do_sigaction() (Frantisek Hrbata) [858752 858753] {CVE-2012-4398}
- Revert: [kernel] Fix ____call_usermodehelper errs being silently ignored (Frantisek Hrbata) [858752 858753] {CVE-2012-4398}
- Revert: [kernel] wait_for_helper: SIGCHLD from u/s cause use-after-free (Frantisek Hrbata) [858752 858753] {CVE-2012-4398}
- Revert: [kernel] kmod: avoid deadlock from recursive request_module call (Frantisek Hrbata) [957152 949568]
- Revert: [x86-64] non lazy sleazy fpu implementation (Prarit Bhargava) [948187 731531]
- Revert: [i386] add sleazy FPU optimization (Prarit Bhargava) [948187 731531]
- Revert: [x86] fpu: fix CONFIG_PREEMPT=y corruption of FPU stack (Prarit Bhargava) [948187 731531]
- Revert: [ia64] fix KABI breakage on ia64 (Prarit Bhargava) [966878 960783]

[2.6.18-348.10.1]
- [net] Bluetooth: fix possible info leak in bt_sock_recvmsg() (Radomir Vrbovsky) [955600 955601] {CVE-2013-3224}
- [net] Bluetooth: HCI & L2CAP information leaks (Jacob Tanenbaum) [922415 922416] {CVE-2012-6544}
- [misc] signal: use __ARCH_HAS_SA_RESTORER instead of SA_RESTORER (Nikola Pajkovsky) [920503 920504] {CVE-2013-0914}
- [misc] signal: always clear sa_restorer on execve (Nikola Pajkovsky) [920503 920504] {CVE-2013-0914}
- [misc] signal: Def __ARCH_HAS_SA_RESTORER for sa_restorer clear (Nikola Pajkovsky) [920503 920504] {CVE-2013-0914}
- [net] cxgb4: zero out another firmware request struct (Jay Fenlason) [971872 872531]
- [net] cxgb4: clear out most firmware request structures (Jay Fenlason) [971872 872531]
- [kernel] Make futex_wait() use an hrtimer for timeout (Prarit Bhargava) [958021 864648]

[2.6.18-348.9.1]
- [net] tg3: buffer overflow in VPD firmware parsing (Jacob Tanenbaum) [949939 949940] {CVE-2013-1929}
- [net] atm: update msg_namelen in vcc_recvmsg() (Nikola Pajkovsky) [955222 955223] {CVE-2013-3222}
- [fs] ext4: prevent race while walking extent tree for fiemap (Lukas Czerner) [960014 692071]
- [fs] ext4: Fix possibly very long loop in fiemap (Lukas Czerner) ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-348.12.1.el5, oracleasm-2.6.18-348.12.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~348.12.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~348.12.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~348.12.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~348.12.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~348.12.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~348.12.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~348.12.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~348.12.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~348.12.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~348.12.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-348.12.1.el5", rpm:"ocfs2-2.6.18-348.12.1.el5~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-348.12.1.el5PAE", rpm:"ocfs2-2.6.18-348.12.1.el5PAE~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-348.12.1.el5debug", rpm:"ocfs2-2.6.18-348.12.1.el5debug~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-348.12.1.el5xen", rpm:"ocfs2-2.6.18-348.12.1.el5xen~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-348.12.1.el5", rpm:"oracleasm-2.6.18-348.12.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-348.12.1.el5PAE", rpm:"oracleasm-2.6.18-348.12.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-348.12.1.el5debug", rpm:"oracleasm-2.6.18-348.12.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-348.12.1.el5xen", rpm:"oracleasm-2.6.18-348.12.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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

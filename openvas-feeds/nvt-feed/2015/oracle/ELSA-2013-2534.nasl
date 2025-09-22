# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123612");
  script_cve_id("CVE-2012-4542", "CVE-2012-6542", "CVE-2013-1860", "CVE-2013-1929", "CVE-2013-1943");
  script_tag(name:"creation_date", value:"2015-10-06 11:06:16 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-03 15:58:00 +0000 (Mon, 03 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2013-2534)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-2534");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-2534.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-uek, mlnx_en-2.6.32-400.29.1.el5uek, mlnx_en-2.6.32-400.29.1.el6uek, ofa-2.6.32-400.29.1.el5uek, ofa-2.6.32-400.29.1.el6uek' package(s) announced via the ELSA-2013-2534 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-400.29.1]
- KVM: add missing void __user COPYING CREDITS Documentation Kbuild MAINTAINERS Makefile README REPORTING-BUGS arch block crypto drivers firmware fs include init ipc kernel lib mm net samples scripts security sound tools uek-rpm usr virt cast to access_ok() call (Heiko Carstens) [Orabug: 16941620] {CVE-2013-1943}
- KVM: Validate userspace_addr of memslot when registered (Takuya Yoshikawa) [Orabug: 16941620] {CVE-2013-1943}

[2.6.32-400.28.1]
- do_add_mount()/umount -l races (Jerry Snitselaar) [Orabug: 16311974]
- tg3: fix length overflow in VPD firmware parsing (Kees Cook) [Orabug: 16837019] {CVE-2013-1929}
- USB: cdc-wdm: fix buffer overflow (Oliver Neukum) [Orabug: 16837003] {CVE-2013-1860}
- bonding: emit event when bonding changes MAC (Weiping Pan) [Orabug: 16579025]
- sched: Fix ancient race in do_exit() (Joe Jin)
- open debug in page_move_anon_rmap by default. (Xiaowei.Hu) [Orabug: 14046035]
- block: default SCSI command filter does not accommodate commands overlap across device classes (Jamie Iles) [Orabug: 16387136] {CVE-2012-4542}
- vma_adjust: fix the copying of anon_vma chains (Linus Torvalds) [Orabug: 14046035]
- xen-netfront: delay gARP until backend switches to Connected (Laszlo Ersek) [Orabug: 16182568]
- svcrpc: don't hold sv_lock over svc_xprt_put() (J. Bruce Fields) [Orabug: 16032824]
- mm/hotplug: correctly add new zone to all other nodes' zone lists (Jiang Liu) [Orabug: 16603569] {CVE-2012-5517}
- ptrace: ptrace_resume() shouldn't wake up !TASK_TRACED thread (Oleg Nesterov) [Orabug: 16405868] {CVE-2013-0871}
- ptrace: ensure arch_ptrace/ptrace_request can never race with SIGKILL (Oleg Nesterov) [Orabug: 16405868] {CVE-2013-0871}
- ptrace: introduce signal_wake_up_state() and ptrace_signal_wake_up() (Oleg Nesterov) [Orabug: 16405868] {CVE-2013-0871}
- Bluetooth: Fix incorrect strncpy() in hidp_setup_hid() (Anderson Lizardo) [Orabug: 16711062] {CVE-2013-0349}
- dccp: check ccid before dereferencing (Mathias Krause) [Orabug: 16711040] {CVE-2013-1827}
- USB: io_ti: Fix NULL dereference in chase_port() (Wolfgang Frisch) [Orabug: 16425435] {CVE-2013-1774}
- keys: fix race with concurrent install_user_keyrings() (David Howells) [Orabug: 16493369] {CVE-2013-1792}
- KVM: Fix bounds checking in ioapic indirect register reads (CVE-2013-1798) (Andy Honig) [Orabug: 16710937] {CVE-2013-1798}
- KVM: x86: fix for buffer overflow in handling of MSR_KVM_SYSTEM_TIME (CVE-2013-1796) (Jerry Snitselaar) [Orabug: 16710794] {CVE-2013-1796}

[2.6.32-400.27.1]
- net/tun: fix ioctl() based info leaks (Mathias Krause) [Orabug: 16675501] {CVE-2012-6547}
- atm: fix info leak via getsockname() (Mathias Krause) [Orabug: 16675501] {CVE-2012-6546}
- atm: fix info leak in getsockopt(SO_ATMPVC) (Mathias Krause) [Orabug: 16675501] {CVE-2012-6546}
- xfrm_user: fix info leak in copy_to_user_tmpl() (Mathias Krause) [Orabug: 16675501] {CVE-2012-6537}
- xfrm_user: fix info ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-uek, mlnx_en-2.6.32-400.29.1.el5uek, mlnx_en-2.6.32-400.29.1.el6uek, ofa-2.6.32-400.29.1.el5uek, ofa-2.6.32-400.29.1.el6uek' package(s) on Oracle Linux 5, Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~400.29.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~400.29.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~400.29.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~400.29.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~400.29.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~400.29.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~400.29.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-400.29.1.el5uek", rpm:"mlnx_en-2.6.32-400.29.1.el5uek~1.5.7~2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-400.29.1.el5uekdebug", rpm:"mlnx_en-2.6.32-400.29.1.el5uekdebug~1.5.7~2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-400.29.1.el5uek", rpm:"ofa-2.6.32-400.29.1.el5uek~1.5.1~4.0.58", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-400.29.1.el5uekdebug", rpm:"ofa-2.6.32-400.29.1.el5uekdebug~1.5.1~4.0.58", rls:"OracleLinux5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~400.29.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~400.29.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~400.29.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~400.29.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~400.29.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~400.29.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~400.29.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-400.29.1.el6uek", rpm:"mlnx_en-2.6.32-400.29.1.el6uek~1.5.7~0.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-400.29.1.el6uekdebug", rpm:"mlnx_en-2.6.32-400.29.1.el6uekdebug~1.5.7~0.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-400.29.1.el6uek", rpm:"ofa-2.6.32-400.29.1.el6uek~1.5.1~4.0.58", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-400.29.1.el6uekdebug", rpm:"ofa-2.6.32-400.29.1.el6uekdebug~1.5.1~4.0.58", rls:"OracleLinux6"))) {
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

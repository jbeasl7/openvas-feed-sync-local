# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123610");
  script_cve_id("CVE-2012-6542", "CVE-2013-1848", "CVE-2013-1860", "CVE-2013-1929", "CVE-2013-1979");
  script_tag(name:"creation_date", value:"2015-10-06 11:06:15 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-2525)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-2525");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-2525.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-uek' package(s) announced via the ELSA-2013-2525 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.39-400.109.1]
- while removing a non-empty directory, the kernel dumps a message: (rmdir,21743,1):ocfs2_unlink:953 ERROR: status = -39 (Xiaowei.Hu) [Orabug: 16790405]
- stop mig handler when lockres in progress ,and return -EAGAIN (Xiaowei.Hu) [Orabug: 16876446]

[2.6.39-400.108.1]
- Revert 'dlmglue race condition,wrong lockres_clear_pending' (Maxim Uvarov) [Orabug: 16897450]
- Suppress the error message from being printed in ocfs2_rename (Xiaowei.Hu) [Orabug: 16790405]
- fnic: return zero on fnic_reset() success (Joe Jin) [Orabug: 16885029]

[2.6.39-400.107.1]
- xen/pci: Track PVHVM PIRQs. (Zhenzhong Duan)
- ocfs2_prep_new_orphaned_file return ret (Xiaowei.Hu) [Orabug: 16823825]
- Revert 'Btrfs: remove ->dirty_inode' (Guangyu Sun) [Orabug: 16841843]
- bonding: emit event when bonding changes MAC (Weiping Pan) [Orabug: 16750157]
- net: fix incorrect credentials passing (Linus Torvalds) [Orabug: 16836975] {CVE-2013-1979}
- tg3: fix length overflow in VPD firmware parsing (Kees Cook) [Orabug: 16836958] {CVE-2013-1929}
- USB: cdc-wdm: fix buffer overflow (Oliver Neukum) [Orabug: 16836943] {CVE-2013-1860}
- ext3: Fix format string issues (Lars-Peter Clausen) [Orabug: 16836934] {CVE-2013-1848}
- cnic: don't use weak dependencies for ipv6 (Jerry Snitselaar) [Orabug: 16780307]
- Revert 'drm/i915: correctly order the ring init sequence' (Guangyu Sun) [Orabug: 16486689]
- x86/boot-image: Don't leak phdrs in arch/x86/boot/compressed/misc.c::Parse_elf() (Jesper Juhl) [Orabug: 16833437]
- spec: add /boot/vmlinuz*.hmac needed for fips mode (John Haxby) [Orabug: 16807114]
- perf: Treat attr.config as u64 in perf_swevent_init() (Tommi Rantala) [Orabug: 16808734] {CVE-2013-2094}
- spec: ol6 add multipath version deps (Maxim Uvarov) [Orabug: 16763586]
- Fix EN driver to work with newer FWs based on latest mlx4_core (Yuval Shaia) [Orabug: 16748891]
- xen-netfront: delay gARP until backend switches to Connected (Laszlo Ersek)
- fuse: enhance fuse dev to be numa aware (Srinivas Eeda) [Orabug: 16218187]
- fuse: add fuse numa node struct (Srinivas Eeda) [Orabug: 16218187]
- fuse: add numa mount option (Srinivas Eeda) [Orabug: 16218187]
- xen-blkfront: use a different scatterlist for each request (Roger Pau Monne) [Orabug: 16660413]
- bonding: allow all slave speeds (Jiri Pirko) [Orabug: 16759490]
- dlmglue race condition,wrong lockres_clear_pending (Xiaowei.Hu) [Orabug: 13611997]

[2.6.39-400.106.0]
- spec: fix suffix order of a directory name (Guangyu Sun) [Orabug: 16682371]
- Merge tag 'v2.6.39-400#qu4bcom' of git://ca-git.us.oracle.com/linux-snits-public into uek2-master (Maxim Uvarov) [Orabug: 16626319]
- Merge tag 'v2.6.39-400#qu4qlge' of git://ca-git.us.oracle.com/linux-snits-public into uek2-master (Maxim Uvarov) [Orabug: 16732027]
- Merge tag 'v2.6.39-400#qu4lpfc' of git://ca-git.us.oracle.com/linux-snits-public into uek2-master (Maxim Uvarov) [Orabug: 16749881]
- block: default ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.109.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.109.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.109.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.109.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.109.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.109.1.el5uek", rls:"OracleLinux5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.109.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.109.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.109.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.109.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.109.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.109.1.el6uek", rls:"OracleLinux6"))) {
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

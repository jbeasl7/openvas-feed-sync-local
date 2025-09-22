# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123959");
  script_cve_id("CVE-2011-4077", "CVE-2011-4081", "CVE-2011-4132", "CVE-2011-4347", "CVE-2011-4594", "CVE-2011-4611", "CVE-2011-4622", "CVE-2012-0038", "CVE-2012-0045", "CVE-2012-0207");
  script_tag(name:"creation_date", value:"2015-10-06 11:10:50 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-30 19:39:00 +0000 (Thu, 30 Jul 2020)");

  script_name("Oracle: Security Advisory (ELSA-2012-0350)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0350");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0350.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2012-0350 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-220.7.1.el6]
- [netdrv] tg3: Fix single-vector MSI-X code (John Feeney) [787162 703555]
- [mm] export remove_from_page_cache() to modules (Jerome Marchand) [772687 751419]
- [block] cfq-iosched: fix cfq_cic_link() race confition (Vivek Goyal) [786022 765673]
- [fs] cifs: lower default wsize when unix extensions are not used (Jeff Layton) [789058 773705]
- [net] svcrpc: fix double-free on shutdown of nfsd after changing pool mode (J. Bruce Fields) [787580 753030]
- [net] svcrpc: avoid memory-corruption on pool shutdown (J. Bruce Fields) [787580 753030]
- [net] svcrpc: destroy server sockets all at once (J. Bruce Fields) [787580 753030]
- [net] svcrpc: simplify svc_close_all (J. Bruce Fields) [787580 753030]
- [net] svcrpc: fix list-corrupting race on nfsd shutdown (J. Bruce Fields) [787580 753030]
- [fs] xfs: Fix missing xfs_iunlock() on error recovery path in xfs_readlink() (Carlos Maiolino) [749161 694702] {CVE-2011-4077}
- [fs] xfs: Fix memory corruption in xfs_readlink (Carlos Maiolino) [749161 694702] {CVE-2011-4077}
- [x86] hpet: Disable per-cpu hpet timer if ARAT is supported (Prarit Bhargava) [772884 750201]
- [x86] Improve TSC calibration using a delayed workqueue (Prarit Bhargava) [772884 750201]
- [kernel] clocksource: Add clocksource_register_hz/khz interface (Prarit Bhargava) [772884 750201]
- [kernel] clocksource: Provide a generic mult/shift factor calculation (Prarit Bhargava) [772884 750201]
- [block] cfq-iosched: fix a kbuild regression (Vivek Goyal) [769208 705698]
- [block] cfq-iosched: rethink seeky detection for SSDs (Vivek Goyal) [769208 705698]
- [block] cfq-iosched: rework seeky detection (Vivek Goyal) [769208 705698]
- [block] cfq-iosched: don't regard requests with long distance as close (Vivek Goyal) [769208 705698]

[2.6.32-220.6.1.el6]
- [scsi] qla2xxx: Module parameter to control use of async or sync port login (Chad Dupuis) [788003 769007]

[2.6.32-220.5.1.el6]
- [net] igmp: Avoid zero delay when receiving odd mixture of IGMP queries (Jiri Pirko) [772870 772871] {CVE-2012-0207}
- [fs] xfs: validate acl count (Eric Sandeen) [773282 773283] {CVE-2012-0038}
- [fs] Fix sendfile write-side file position (Steven Whitehouse) [771870 770023]
- [virt] kvm: x86: fix missing checks in syscall emulation (Marcelo Tosatti) [773390 773391] {CVE-2012-0045}
- [virt] kvm: x86: extend 'struct x86_emulate_ops' with 'get_cpuid' (Marcelo Tosatti) [773390 773391] {CVE-2012-0045}
- [fs] nfs: when attempting to open a directory, fall back on normal lookup (Jeff Layton) [771981 755380]
- [kernel] crypto: ghash - Avoid null pointer dereference if no key is set (Jiri Benc) [749481 749482] {CVE-2011-4081}
- [fs] jbd2: validate sb->s_first in journal_get_superblock() (Eryu Guan) [753344 693981] {CVE-2011-4132}
- [net] fix unsafe pointer access in sendmmsg (Jiri Benc) [761668 760798] {CVE-2011-4594}
- [scsi] increase qla2xxx firmware ready time-out (Mark Goodwin) ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~220.7.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~220.7.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~220.7.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~220.7.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~220.7.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~220.7.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~220.7.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~220.7.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~220.7.1.el6", rls:"OracleLinux6"))) {
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

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.2292.1");
  script_cve_id("CVE-2015-0272", "CVE-2015-2925", "CVE-2015-5156", "CVE-2015-7799", "CVE-2015-7872", "CVE-2015-7990", "CVE-2015-8215");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-12-28 19:44:20 +0000 (Mon, 28 Dec 2015)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:2292-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:2292-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20152292-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/758040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/814440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921949");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924493");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/926238");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/939826");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/939926");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940776");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/941113");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/941202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/943959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/947241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/947478");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949936");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951165");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951864");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/952384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/952666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953826");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953971");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953980");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955533");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956047");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956147");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956284");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957546");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958647");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-December/001736.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2015:2292-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP1 kernel was updated to 3.12.51 to receive various security and bugfixes.

Following features were added:
- hwrng: Add a driver for the hwrng found in power7+ systems (fate#315784).

Following security bugs were fixed:
- CVE-2015-8215: net/ipv6/addrconf.c in the IPv6 stack in the Linux
 kernel did not validate attempted changes to the MTU value, which allowed
 context-dependent attackers to cause a denial of service (packet loss)
 via a value that is (1) smaller than the minimum compliant value or
 (2) larger than the MTU of an interface, as demonstrated by a Router
 Advertisement (RA) message that is not validated by a daemon, a different
 vulnerability than CVE-2015-0272. (bsc#955354)
- CVE-2015-5156: The virtnet_probe function in drivers/net/virtio_net.c in
 the Linux kernel attempted to support a FRAGLIST feature without proper
 memory allocation, which allowed guest OS users to cause a denial of
 service (buffer overflow and memory corruption) via a crafted sequence
 of fragmented packets (bnc#940776).
- CVE-2015-7872: The key_gc_unused_keys function in security/keys/gc.c
 in the Linux kernel allowed local users to cause a denial of service
 (OOPS) via crafted keyctl commands (bnc#951440).
- CVE-2015-7799: The slhc_init function in drivers/net/slip/slhc.c in
 the Linux kernel did not ensure that certain slot numbers are valid,
 which allowed local users to cause a denial of service (NULL
 pointer dereference and system crash) via a crafted PPPIOCSMAXCID ioctl
 call (bnc#949936).
- CVE-2015-2925: The prepend_path function in fs/dcache.c in the Linux
 kernel did not properly handle rename actions inside a bind mount, which
 allowed local users to bypass an intended container protection mechanism
 by renaming a directory, related to a 'double-chroot attack (bnc#926238).
- CVE-2015-7990: RDS: Verify the underlying transport exists before
 creating a connection, preventing possible DoS (bsc#952384).

The following non-security bugs were fixed:
- af_iucv: avoid path quiesce of severed path in shutdown() (bnc#954986, LTC#131684).
- alsa: hda - Disable 64bit address for Creative HDA controllers (bnc#814440).
- alsa: hda - Fix noise problems on Thinkpad T440s (boo#958504).
- alsa: hda - Fix noise problems on Thinkpad T440s (boo#958504).
- apparmor: allow SYS_CAP_RESOURCE to be sufficient to prlimit another task (bsc#921949).
- audit: correctly record file names with different path name types (bsc#950013).
- audit: create private file name copies when auditing inodes (bsc#950013).
- bcache: Add btree_insert_node() (bnc#951638).
- bcache: Add explicit keylist arg to btree_insert() (bnc#951638).
- bcache: backing device set to clean after finishing detach (bsc#951638).
- bcache: backing device set to clean after finishing detach (bsc#951638).
- bcache: Clean up keylist code (bnc#951638).
- bcache: Convert btree_insert_check_key() to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.51~60.20.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.51~60.20.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.51~60.20.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.51~60.20.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.51~60.20.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.51~60.20.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.51~60.20.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.51~60.20.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.51~60.20.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.51~60.20.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.51~60.20.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.51~60.20.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.51~60.20.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.51~60.20.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.51~60.20.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.51~60.20.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.51~60.20.2", rls:"SLES12.0SP1"))) {
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

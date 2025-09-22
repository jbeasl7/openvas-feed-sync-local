# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.2194.1");
  script_cve_id("CVE-2015-0272", "CVE-2015-2925", "CVE-2015-5283", "CVE-2015-5307", "CVE-2015-7799", "CVE-2015-7872", "CVE-2015-7990", "CVE-2015-8104", "CVE-2015-8215");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-12-28 19:44:20 +0000 (Mon, 28 Dec 2015)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:2194-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:2194-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20152194-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/814440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/867595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921949");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924493");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936076");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/939826");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/939926");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/941202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/941867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945626");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/946078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/947241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/947321");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/947478");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948521");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950862");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951165");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951546");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/952666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/952758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953980");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955533");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956047");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956711");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-December/001718.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2015:2194-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 kernel was updated to 3.12.51 to receive various security and bugfixes.

Following security bugs were fixed:
- CVE-2015-7799: The slhc_init function in drivers/net/slip/slhc.c in the Linux kernel did not ensure that certain slot numbers were valid, which allowed local users to cause a denial of service (NULL pointer dereference and system crash) via a crafted PPPIOCSMAXCID ioctl call (bnc#949936).
- CVE-2015-5283: The sctp_init function in net/sctp/protocol.c in the Linux kernel had an incorrect sequence of protocol-initialization steps, which allowed local users to cause a denial of service (panic or memory corruption) by creating SCTP sockets before all of the steps have finished (bnc#947155).
- CVE-2015-2925: The prepend_path function in fs/dcache.c in the Linux kernel did not properly handle rename actions inside a bind mount, which allowed local users to bypass an intended container protection mechanism by renaming a directory, related to a 'double-chroot attack (bnc#926238).
- CVE-2015-8104: The KVM subsystem in the Linux kernel allowed guest OS users to cause a denial of service (host OS panic or hang) by triggering many #DB (aka Debug) exceptions, related to svm.c (bnc#954404).
- CVE-2015-5307: The KVM subsystem in the Linux kernel allowed guest OS users to cause a denial of service (host OS panic or hang) by triggering many #AC (aka Alignment Check) exceptions, related to svm.c and vmx.c (bnc#953527).
- CVE-2015-7990: RDS: There was no verification that an underlying transport exists when creating a connection, causing usage of a NULL pointer (bsc#952384).
- CVE-2015-7872: The key_gc_unused_keys function in security/keys/gc.c in the Linux kernel allowed local users to cause a denial of service (OOPS) via crafted keyctl commands (bnc#951440).
- CVE-2015-0272: Missing checks allowed remote attackers to cause a denial of service (IPv6 traffic disruption) via a crafted MTU value in an IPv6 Router Advertisement (RA) message, a different vulnerability than CVE-2015-8215 (bnc#944296).

The following non-security bugs were fixed:
- ALSA: hda - Disable 64bit address for Creative HDA controllers (bnc#814440).
- Add PCI IDs of Intel Sunrise Point-H SATA Controller S232/236 (bsc#953796).
- Btrfs: fix file corruption and data loss after cloning inline extents (bnc#956053).
- Btrfs: fix truncation of compressed and inlined extents (bnc#956053).
- Disable some ppc64le netfilter modules to restore the kabi (bsc#951546)
- Fix regression in NFSRDMA server (bsc#951110).
- KEYS: Fix race between key destruction and finding a keyring by name (bsc#951440).
- KVM: x86: call irq notifiers with directed EOI (bsc#950862).
- NVMe: Add shutdown timeout as module parameter (bnc#936076).
- NVMe: Mismatched host/device page size support (bsc#935961).
- PCI: Drop 'setting latency timer' messages (bsc#956047).
- SCSI: Fix hard lockup in scsi_remove_target() ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.51~52.31.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.51~52.31.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.51~52.31.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.51~52.31.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.51~52.31.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.51~52.31.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.51~52.31.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.51~52.31.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.51~52.31.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.51~52.31.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.51~52.31.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.51~52.31.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.51~52.31.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.51~52.31.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.51~52.31.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.51~52.31.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.51~52.31.1", rls:"SLES12.0"))) {
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

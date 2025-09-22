# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0178.1");
  script_cve_id("CVE-2014-3687", "CVE-2014-3690", "CVE-2014-8559", "CVE-2014-9420", "CVE-2014-9585");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-11-10 14:26:04 +0000 (Mon, 10 Nov 2014)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0178-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0178-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150178-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2015:0178-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 kernel was updated to 3.12.36 to receive various security and bugfixes.

Following security bugs were fixed:
- CVE-2014-8559: The d_walk function in fs/dcache.c in the Linux kernel
 through 3.17.2 did not properly maintain the semantics of rename_lock,
 which allowed local users to cause a denial of service (deadlock and
 system hang) via a crafted application (bnc#903640).
- CVE-2014-9420: The rock_continue function in fs/isofs/rock.c in the
 Linux kernel through 3.18.1 did not restrict the number of Rock Ridge
 continuation entries, which allowed local users to cause a denial of
 service (infinite loop, and system crash or hang) via a crafted iso9660
 image (bnc#906545 911325).
- CVE-2014-3690: arch/x86/kvm/vmx.c in the KVM subsystem in the Linux
 kernel before 3.17.2 on Intel processors did not ensure that the value
 in the CR4 control register remained the same after a VM entry, which
 allowed host OS users to kill arbitrary processes or cause a denial of
 service (system disruption) by leveraging /dev/kvm access, as
 demonstrated by PR_SET_TSC prctl calls within a modified copy of QEMU
 (bnc#902232).
- CVE-2014-3687: The sctp_assoc_lookup_asconf_ack function in
 net/sctp/associola.c in the SCTP implementation in the Linux kernel
 through 3.17.2 allowed remote attackers to cause a denial of service
 (panic) via duplicate ASCONF chunks that triggered an incorrect uncork
 within the side-effect interpreter (bnc#902349).
- CVE-2014-9585: The vdso_addr function in arch/x86/vdso/vma.c in the
 Linux kernel through 3.18.2 did not properly choose memory locations for
 the vDSO area, which made it easier for local users to bypass the ASLR
 protection mechanism by guessing a location at the end of a PMD
 (bnc#912705).

The following non-security bugs were fixed:
- ACPI idle: permit sparse C-state sub-state numbers (bnc#907969).
- ALSA: hda - verify pin:converter connection on unsol event for HSW and
 VLV.
- ALSA: hda - verify pin:cvt connection on preparing a stream for Intel
 HDMI codec.
- ALSA: hda/hdmi - apply Valleyview fix-ups to Cherryview display codec.
- ALSA: hda_intel: Add Device IDs for Intel Sunrise Point PCH.
- ALSA: hda_intel: Add DeviceIDs for Sunrise Point-LP.
- Btrfs: Disable
 patches.suse/Btrfs-fix-abnormal-long-waiting-in-fsync.patch (bnc#910697)
 because it needs to be revisited due partial msync behavior.
- Btrfs: Fix misuse of chunk mutex (bnc#912514).
- Btrfs: always clear a block group node when removing it from the tree
 (bnc#912514).
- Btrfs: collect only the necessary ordered extents on ranged fsync
 (bnc#912946).
- Btrfs: do not access non-existent key when csum tree is empty.
- Btrfs: do not delay inode ref updates during log replay.
- Btrfs: do not ignore log btree writeback errors (bnc#912946).
- Btrfs: ensure btrfs_prev_leaf does not miss 1 item.
- Btrfs: ensure deletion from pinned_chunks list is protected ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Build System Kit 12, SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Module for Public Cloud 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Software Development Kit 12, SUSE Linux Enterprise Workstation Extension 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.36~38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.36~38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.36~38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.36~38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.36~38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.36~38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.36~38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.36~38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~3.12.36~38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~3.12.36~38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~3.12.36~38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.36~38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.36~38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.36~38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.36~38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.36~38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.36~38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.36~38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.36~38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base-debuginfo", rpm:"kernel-xen-base-debuginfo~3.12.36~38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-debuginfo", rpm:"kernel-xen-debuginfo~3.12.36~38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-debugsource", rpm:"kernel-xen-debugsource~3.12.36~38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.36~38.1", rls:"SLES12.0"))) {
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

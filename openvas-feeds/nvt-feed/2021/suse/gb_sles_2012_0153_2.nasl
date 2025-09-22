# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0153.2");
  script_cve_id("CVE-2010-3873", "CVE-2010-4164", "CVE-2011-2494", "CVE-2011-2699", "CVE-2011-4077", "CVE-2011-4081", "CVE-2011-4110", "CVE-2011-4127", "CVE-2011-4132", "CVE-2012-0038");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:28 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2012-05-25 15:18:00 +0000 (Fri, 25 May 2012)");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0153-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0153-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120153-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux kernel' package(s) announced via the SUSE-SU-2012:0153-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP1 kernel was updated to 2.6.32.54, fixing lots of bugs and security issues.

The following security issues have been fixed:

 * CVE-2011-4127: A potential hypervisor escape by issuing SG_IO commands to partitiondevices was fixed by restricting access to these commands.
 * CVE-2011-4110: KEYS: Fix a NULL pointer deref in the user-defined key type, which allowed local attackers to Oops the kernel.
 * CVE-2011-4081: Avoid potential NULL pointer deref in ghash, which allowed local attackers to Oops the kernel.
 * CVE-2011-4077: Fixed a memory corruption possibility in xfs readlink, which could be used by local attackers to crash the system or potentially execute code by mounting a prepared xfs filesystem image.
 * CVE-2012-0038: A overflow in the xfs acl handling was fixed that could be used by local attackers to crash the system or potentially execute code by mounting a prepared xfs filesystem image.
 * CVE-2011-4132: A flaw in the ext3/ext4 filesystem allowed a local attacker to crash the kernel by getting a prepared ext3/ext4 filesystem mounted.
 * CVE-2011-2494: Access to the taskstats /proc file was restricted to avoid local attackers gaining knowledge of IO of other users (and so effecting side-channel attacks for e.g. guessing passwords by typing speed).
 * CVE-2010-3873: When using X.25 communication a malicious sender could corrupt data structures, causing crashes or potential code execution. Please note that X.25 needs to be setup to make this effective, which these days is usually not the case.
 * CVE-2010-4164: When using X.25 communication a malicious sender could make the machine leak memory,
causing crashes. Please note that X.25 needs to be setup to make this effective, which these days is usually not the case.
 * CVE-2011-2699: A remote denial of service due to a NULL pointer dereference by using IPv6 fragments was fixed.

The following non-security issues have been fixed:

 * elousb: Fixed bug in USB core API usage, code cleanup
(bnc#733863).
 * cifs: overhaul cifs_revalidate and rename to cifs_revalidate_dentry (bnc#735453).
 * cifs: set server_eof in cifs_fattr_to_inode
(bnc#735453).
 * xfs: Fix missing xfs_iunlock() on error recovery path in xfs_readlink() (bnc#726600).
 * block: add and use scsi_blk_cmd_ioctl (bnc#738400 CVE-2011-4127).
 * block: fail SCSI passthrough ioctls on partition devices (bnc#738400 CVE-2011-4127).
 * dm: do not forward ioctls from logical volumes to the underlying device (bnc#738400 CVE-2011-4127).
 * Silence some warnings about ioctls on partitions.
 * netxen: Remove all references to unified firmware file (bnc#708625).
 * bonding: send out gratuitous arps even with no address configured (bnc#742270).
 * patches.fixes/ocfs2-serialize_unaligned_aio.patch:
ocfs2: serialize unaligned aio (bnc#671479).
 *
patches.fixes/bonding-check-if-clients-MAC-addr-has-changed.
patch: Update references ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux kernel' package(s) on SUSE Linux Enterprise Desktop 11-SP1, SUSE Linux Enterprise High Availability Extension 11-SP1, SUSE Linux Enterprise Server 11-SP1.");

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

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"btrfs-kmp-default", rpm:"btrfs-kmp-default~0_2.6.32.54_0.3~0.3.73", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"btrfs-kmp-xen", rpm:"btrfs-kmp-xen~0_2.6.32.54_0.3~0.3.73", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ext4dev-kmp-default", rpm:"ext4dev-kmp-default~0_2.6.32.54_0.3~7.9.40", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ext4dev-kmp-trace", rpm:"ext4dev-kmp-trace~0_2.6.32.54_0.3~7.9.40", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ext4dev-kmp-xen", rpm:"ext4dev-kmp-xen~0_2.6.32.54_0.3~7.9.40", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hyper-v-kmp-default", rpm:"hyper-v-kmp-default~0_2.6.32.54_0.3~0.18.3", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hyper-v-kmp-trace", rpm:"hyper-v-kmp-trace~0_2.6.32.54_0.3~0.18.3", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.32.54~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~2.6.32.54~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~2.6.32.54~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~2.6.32.54~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~2.6.32.54~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.32.54~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.32.54~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~2.6.32.54~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~2.6.32.54~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~2.6.32.54~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.32.54~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~2.6.32.54~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.32.54~0.3.1", rls:"SLES11.0SP1"))) {
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

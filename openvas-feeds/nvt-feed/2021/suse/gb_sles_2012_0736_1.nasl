# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0736.1");
  script_cve_id("CVE-2011-2928", "CVE-2011-4077", "CVE-2011-4324", "CVE-2011-4330", "CVE-2012-2313", "CVE-2012-2319");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:27 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0736-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0736-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120736-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux kernel' package(s) announced via the SUSE-SU-2012:0736-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This Linux kernel update fixes various security issues and bugs in the SUSE Linux Enterprise 10 SP4 kernel.

The following security issues have been fixed:

 *

 CVE-2012-2319: A memory corruption when mounting a hfsplus filesystem was fixed that could be used by local attackers able to mount filesystem to crash the system.

 *

 CVE-2012-2313: The dl2k network card driver lacked permission handling for some ethtool ioctls, which could allow local attackers to start/stop the network card.

 *

 CVE-2011-2928: The befs_follow_linkl function in fs/befs/linuxvfs.c in the Linux kernel did not validate the lenght attribute of long symlinsk, which allowed local users to cause a denial of service (incorrect pointer dereference and Ooops) by accessing a long symlink on a malformed Be filesystem.

 *

 CVE-2011-4077: Fixed a memory corruption possibility in xfs readlink, which could be used by local attackers to crash the system or potentially execute code by mounting a prepared xfs filesystem image.

 *

 CVE-2011-4324: A BUG() error report in the nfs4xdr routines on a NFSv4 mount was fixed that could happen during mknod.

 *

 CVE-2011-4330: Mounting a corrupted hfs filesystem could lead to a buffer overflow.

The following non-security issues have been fixed:

 * kernel: pfault task state race (bnc#764128,LTC#81724).
 * ap: Toleration for ap bus devices with device type 10
(bnc#761389).
 * hugetlb, numa: fix interleave mpol reference count
(bnc#762111).
 * cciss: fixup kdump (bnc#730200).
 * kdump: Avoid allocating bootmem map over crash reserved region (bnc#749168, bnc#722400, bnc#742881).
 * qeth: Improve OSA Express 4 blkt defaults
(bnc#754964,LTC#80325).
 * zcrypt: Fix parameter checking for ZSECSENDCPRB ioctl
(bnc#754964,LTC#80378).
 * virtio: add names to virtqueue struct, mapping from devices to queues (bnc#742148).
 * virtio: find_vqs/del_vqs virtio operations
(bnc#742148).
 * virtio_pci: optional MSI-X support (bnc#742148).
 * virtio_pci: split up vp_interrupt (bnc#742148).
 * knfsd: nfsd4: fix laundromat shutdown race (752556).
 * driver core: Check for valid device in bus_find_device() (bnc#729685).
 * VMware detection backport from mainline (bnc#671124,
bnc#747381).
 * net: adding memory barrier to the poll and receive callbacks (bnc#746397 bnc#750928).
 * qla2xxx: drop reference before wait for completion
(bnc#744592).
 * qla2xxx: drop reference before wait for completion
(bnc#744592).
 * ixgbe driver sets all WOL flags upon initialization so that machine is powered on as soon at it is switched off
(bnc#693639)
 * Properly release MSI(X) vector(s) when MSI(X) gets disabled (bnc#723294, bnc#721869).
 * scsi: Always retry internal target error (bnc#745640).
 * cxgb4: fix parent device access in netdev_printk
(bnc#733155).
 * lcs: lcs offline failure (bnc#752486,LTC#79788).
 * qeth: add missing wake_up call (bnc#752486,LTC#79899).
 * NFSD: Fill in WCC data for ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux kernel' package(s) on SUSE Linux Enterprise Desktop 10-SP4, SUSE Linux Enterprise Server 10-SP4.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.16.60~0.97.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.16.60~0.97.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.16.60~0.97.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-iseries64", rpm:"kernel-iseries64~2.6.16.60~0.97.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.16.60~0.97.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kdumppae", rpm:"kernel-kdumppae~2.6.16.60~0.97.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~2.6.16.60~0.97.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.16.60~0.97.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.16.60~0.97.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.16.60~0.97.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vmi", rpm:"kernel-vmi~2.6.16.60~0.97.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vmipae", rpm:"kernel-vmipae~2.6.16.60~0.97.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.16.60~0.97.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.16.60~0.97.1", rls:"SLES10.0SP4"))) {
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

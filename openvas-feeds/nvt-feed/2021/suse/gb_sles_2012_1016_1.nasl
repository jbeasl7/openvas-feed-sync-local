# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.1016.1");
  script_cve_id("CVE-2012-3375", "CVE-2012-3400");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:27 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:1016-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:1016-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20121016-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel update for SLE11 SP2' package(s) announced via the SUSE-SU-2012:1016-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP2 kernel was updated to 3.0.38, fixing various bugs and security issues.

Following security issues were fixed: CVE-2012-3400:
Several buffer overread and overwrite errors in the UDF logical volume descriptor code were fixed that might have allowed local attackers able to mount UDF volumes to crash the kernel or potentially gain privileges.

CVE-2012-3375: A denial of service (crash) in epoll was fixed.


The three NTP leapsecond issues were fixed and are contained in Linux Kernel stable 3.0.38.

The Libceph/ceph/rbd framework was imported for later Cloud storage usage.

Various bug and security fixes were integrated from the Linux stable kernel 3.0.34-3.0.38 upgrade and are not explicitly listed here.

Following other non-security issues were fixed: S/390:
- dasd: Use correct queue for aborting requests.
- dasd: Abort requests from correct queue.
- [S390] Do not clobber personality flags on exec
 (bnc#770034).
- dasd: Kick tasklet instead of processing the
 request_queue directly.
- s390/kernel: CPU idle vs CPU hotplug
 (bnc#772407,LTC#83468).
- lgr: Make lgr_page static (bnc#772407,LTC#83520).
- s390/kernel: incorrect task size after fork of a 31 bit
 process (bnc#772407,LTC#83674).
- dasd: Abort all requests on the request_queue, too
 (bnc#768084).
- DASD: Add timeout attribute (bnc#771361).
- dasd: Fixup typo in debugging message.
- patches.suse/dasd-fail-all-requests-after-timeout.patch:
 Fixup handling of failfast requests (bnc#768084).
- s390: allow zcrypt to /dev/random feeding to be resumed
 (bnc#718910)
- s390/hypfs: Missing files and directories
 (bnc#769407,LTC#82838).
- dasd: Fail all requests after timeout (bnc#768084).
- s390/kernel: Add z/VM LGR detection
 (bnc#767281,LTC#RAS1203).

BTRFS fixes (3.3-3.5+)
- Btrfs: avoid sleeping in verify_parent_transid while
 atomic
- Btrfs: fix btrfs_release_extent_buffer_page with the
 right usage of num_extent_pages
- Btrfs: do not check delalloc when updating disk_i_size
- Btrfs: look into the extent during find_all_leafs
- Btrfs: do not set for_cow parameter for tree block
 functions
- Btrfs: fix defrag regression
- Btrfs: fix missing inherited flag in rename
- Btrfs: do not resize a seeding device
- Btrfs: cast devid to unsigned long long for printk %llu
- Btrfs: add a missing spin_lock
- Btrfs: restore restriper state on all mounts
- Btrfs: resume balance on rw (re)mounts properly
- Btrfs: fix tree log remove space corner case
- Btrfs: hold a ref on the inode during writepages
- Btrfs: do not return EINVAL instead of ENOMEM from
 open_ctree()
- Btrfs: do not ignore errors from btrfs_cleanup_fs_roots()
 when mounting
- Btrfs: fix error handling in __add_reloc_root()
- Btrfs: return error of btrfs_update_inode() to caller
- Btrfs: fix typo in cow_file_range_async and
 async_cow_submit
- Btrfs: fix btrfs_is_free_space_inode to recognize btree
 inode
- Btrfs: kill root from ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel update for SLE11 SP2' package(s) on SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise High Availability Extension 11-SP2, SUSE Linux Enterprise Server 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.38~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.38~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.38~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.38~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.38~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.38~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.38~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.38~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.38~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.38~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.38~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.38~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.38~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.38~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.38~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.38~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.38~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.38~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.38~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.38~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.38~0.5.1", rls:"SLES11.0SP2"))) {
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

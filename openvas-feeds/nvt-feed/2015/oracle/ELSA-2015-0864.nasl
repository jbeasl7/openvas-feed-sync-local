# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123129");
  script_cve_id("CVE-2014-3215", "CVE-2014-3690", "CVE-2014-7825", "CVE-2014-7826", "CVE-2014-8171", "CVE-2014-8884", "CVE-2014-9529", "CVE-2014-9584", "CVE-2015-1421");
  script_tag(name:"creation_date", value:"2015-10-06 10:59:43 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 18:19:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2015-0864)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-0864");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-0864.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2015-0864 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-504.16.2]
- [infiniband] core: Prevent integer overflow in ib_umem_get address arithmetic (Doug Ledford) [1181173 1179327] {CVE-2014-8159}

[2.6.32-504.16.1]
- [fs] gfs2: Move gfs2_file_splice_write outside of #ifdef (Robert S Peterson) [1198329 1193559]
- [security] keys: close race between key lookup and freeing (Radomir Vrbovsky) [1179849 1179850] {CVE-2014-9529}
- [net] sctp: fix slab corruption from use after free on INIT collisions (Daniel Borkmann) [1196587 1135425] {CVE-2015-1421}
- [fs] gfs2: Allocate reservation during splice_write (Robert S Peterson) [1198329 1193559]
- [fs] nfs: Be less aggressive about returning delegations for open files (Steve Dickson) [1196314 1145334]
- [fs] nfs: Avoid PUTROOTFH when managing leases (Benjamin Coddington) [1196313 1143013]
- [crypto] testmgr: mark rfc4106(gcm(aes)) as fips_allowed (Jarod Wilson) [1194983 1185395]
- [crypto] Extending the RFC4106 AES-GCM test vectors (Jarod Wilson) [1194983 1185395]
- [char] raw: Return short read or 0 at end of a raw device, not EIO (Jeff Moyer) [1195747 1142314]
- [scsi] hpsa: Use local workqueues instead of system workqueues - part1 (Tomas Henzl) [1193639 1134115]
- [x86] kvm: vmx: invalid host cr4 handling across vm entries (Jacob Tanenbaum) [1153326 1153327] {CVE-2014-3690}
- [fs] isofs: Fix unchecked printing of ER records (Radomir Vrbovsky) [1180481 1180492] {CVE-2014-9584}
- [fs] bio: fix argument of __bio_add_page() for max_sectors > 0xffff (Fam Zheng) [1198428 1166763]
- [media] ttusb-dec: buffer overflow in ioctl (Alexander Gordeev) [1170971 1167115] {CVE-2014-8884}
- [kernel] trace: insufficient syscall number validation in perf and ftrace subsystems (Jacob Tanenbaum) [1161567 1161568] {CVE-2014-7826 CVE-2014-7825}
- [fs] nfs: Fix a delegation callback race (Dave Wysochanski) [1187639 1149831]
- [fs] nfs: Don't use the delegation->inode in nfs_mark_return_delegation() (Dave Wysochanski) [1187639 1149831]
- [infiniband] ipoib: don't queue a work struct up twice (Doug Ledford) [1187664 1187666 1184072 1159925]
- [infiniband] ipoib: make sure we reap all our ah on shutdown (Doug Ledford) [1187664 1187666 1184072 1159925]
- [infiniband] ipoib: cleanup a couple debug messages (Doug Ledford) [1187664 1187666 1184072 1159925]
- [infiniband] ipoib: flush the ipoib_workqueue on unregister (Doug Ledford) [1187664 1187666 1184072 1159925]
- [infiniband] ipoib: fix ipoib_mcast_restart_task (Doug Ledford) [1187664 1187666 1184072 1159925]
- [infiniband] ipoib: fix race between mcast_dev_flush and mcast_join (Doug Ledford) [1187664 1187666 1184072 1159925]
- [infiniband] ipoib: remove unneeded locks (Doug Ledford) [1187664 1187666 1184072 1159925]
- [infiniband] ipoib: don't restart our thread on ENETRESET (Doug Ledford) [1187664 1187666 1184072 1159925]
- [infiniband] ipoib: Handle -ENETRESET properly in our callback (Doug Ledford) [1187664 1187666 1184072 1159925]
- [infiniband] ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~504.16.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~504.16.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~504.16.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~504.16.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~504.16.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~504.16.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~504.16.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~504.16.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~504.16.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~504.16.2.el6", rls:"OracleLinux6"))) {
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

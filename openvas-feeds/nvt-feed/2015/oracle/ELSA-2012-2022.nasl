# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123875");
  script_tag(name:"creation_date", value:"2015-10-06 11:09:43 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-01-11 11:33:45 +0000 (Tue, 11 Jan 2022)");

  script_name("Oracle: Security Advisory (ELSA-2012-2022)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-2022");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-2022.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-uek' package(s) announced via the ELSA-2012-2022 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.39-200.24.1.el5uek]
- Revert 'Add Oracle VM guest messaging driver' (Guru Anbalagane) [Orabug: 14233627}

[2.6.39-200.23.1.el5uek]
- SPEC: add block/net modules to list used by installer (Guru Anbalagane)
 [Orabug: 14224837]

[2.6.39-200.22.1.el5uek]
- NFSv4: include bitmap in nfsv4 get acl data (Andy Adamson) {CVE-2011-4131}
- ocfs2:btrfs: aio-dio-loop changes broke setrlimit behavior [orabug 14207636]
 (Dave Kleikamp)
- Add Oracle VM guest messaging driver (Zhigang Wang)
- thp: avoid atomic64_read in pmd_read_atomic for 32bit PAE (Andrea Arcangeli)
 [Orabug: 14217003]

[2.6.39-200.21.0.el5uek]
- KVM: Fix buffer overflow in kvm_set_irq() (Avi Kivity) [Bugdb: 13966]
 {CVE-2012-2137}
- net: sock: validate data_len before allocating skb in sock_alloc_send_pskb()
 (Jason Wang) [Bugdb: 13966] {CVE-2012-2136}
- mm: pmd_read_atomic: fix 32bit PAE pmd walk vs pmd_populate SMP race
 condition (Andrea Arcangeli) [Bugdb: 13966] {CVE-2012-2373}
- KVM: lock slots_lock around device assignment (Alex Williamson) [Bugdb:
 13966] {CVE-2012-2121}
- KVM: unmap pages from the iommu when slots are removed (Alex Williamson)
 [Bugdb: 13966] {CVE-2012-2121}
- KVM: introduce kvm_for_each_memslot macro (Xiao Guangrong) [Bugdb: 13966]
- fcaps: clear the same personality flags as suid when fcaps are used (Eric
 Paris) [Bugdb: 13966] {CVE-2012-2123}

[2.6.39-200.20.0.el5uek]
- Update lpfc version for 8.3.5.68.6p driver release (Martin K. Petersen)
- Fix system hang due to bad protection module parameters (CR 130769) (Martin
 K. Petersen)
- oracleasm: Data integrity support (Martin K. Petersen)
- sd: Allow protection_type to be overridden (Martin K. Petersen)
- SCSI: Fix two bugs in DIX retry handling (Martin K. Petersen)
- sd: Avoid remapping bad reference tags (Martin K. Petersen)
- block: Fix bad range check in bio_sector_offset (Martin K. Petersen)

[2.6.39-200.19.0.el5uek]
- xen/netback: Calculate the number of SKB slots required correctly (Simon
 Graham)

 [2.6.39-200.18.0.el5uek]
- e1000e: disable rxhash when try to enable jumbo frame also rxhash and rxcsum
 have enabled (Joe Jin)

[2.6.39-200.17.0.el5uek]
- mm: reduce the amount of work done when updating min_free_kbytes (Mel Gorman)
 [Orabug: 14073214]
- ocfs2: clear unaligned io flag when dio fails (Junxiao Bi) [Orabug: 14063941]
- aio: make kiocb->private NUll in init_sync_kiocb() (Junxiao Bi) [Orabug:
 14063941]
- vmxnet3: cap copy length at size of skb to prevent dropped frames on tx (Neil
 Horman) [Orabug: 14159701]
- mm/mempolicy.c: refix mbind_range() vma issue (KOSAKI Motohiro) [Orabug:
 14149364]
- mm/mempolicy.c: fix pgoff in mbind vma merge (Caspar Zhang) [Orabug:14149364]

[2.6.39-200.16.0.el5uek]
- xen/gntdev: Fix merge error. (Konrad Rzeszutek Wilk)

[2.6.39-200.15.0.el5uek]
- xen: expose host uuid via sysfs. (Zhigang Wang)

[2.6.39-200.14.0.el5uek]
- SPEC: upgrade preserve rhck as a boot kernel (Kevin Lyons) [Orabug: ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~200.24.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~200.24.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~200.24.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~200.24.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~200.24.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~200.24.1.el5uek", rls:"OracleLinux5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~200.24.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~200.24.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~200.24.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~200.24.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~200.24.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~200.24.1.el6uek", rls:"OracleLinux6"))) {
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

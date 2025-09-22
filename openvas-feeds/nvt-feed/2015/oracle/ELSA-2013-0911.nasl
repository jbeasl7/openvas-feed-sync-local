# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123611");
  script_cve_id("CVE-2013-1935", "CVE-2013-1943", "CVE-2013-2017");
  script_tag(name:"creation_date", value:"2015-10-06 11:06:16 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-03 15:58:00 +0000 (Mon, 03 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2013-0911)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0911");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0911.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2013-0911 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-358.11.1]
- [kernel] perf: fix perf_swevent_enabled array out-of-bound access (Petr Matousek) [962793 962794] {CVE-2013-2094}

[2.6.32-358.10.1]
- [scsi] be2iscsi : Fix the NOP-In handling code path (Nikola Pajkovsky) [955504 947550]
- [scsi] be2iscsi: Fix memory leak in control path of driver (Rob Evers) [955504 947550]
- [virt] kvm: validate userspace_addr of memslot (Petr Matousek) [950496 950498] {CVE-2013-1943}
- [virt] kvm: fix copy to user with irq disabled (Michael S. Tsirkin) [949985 906602] {CVE-2013-1935}
- [net] veth: Don't kfree_skb() after dev_forward_skb() (Jiri Benc) [957712 957713] {CVE-2013-2017}
- [net] tcp: Reallocate headroom if it would overflow csum_start (Thomas Graf) [954298 896233]
- [net] tcp: take care of misalignments (Thomas Graf) [954298 896233]
- [net] skbuff.c cleanup (Thomas Graf) [954298 896233]
- [idle] intel_idle: Initialize driver_data correctly in ivb_cstates on IVB processor (Prarit Bhargava) [960864 953630]
- [x86] Prevent panic in init_memory_mapping() when booting more than 1TB on AMD systems (Larry Woodman) [962482 869736]
- [mm] enforce mmap_min_addr on x86_64 (Rik van Riel) [961431 790921]
- [mm] optional next-fit policy for arch_get_unmapped_area (Rik van Riel) [961431 790921]
- [mm] fix quadratic behaviour in get_unmapped_area_topdown (Rik van Riel) [961431 790921]
- [scsi] Revert: qla2xxx: Optimize existing port name server query matching (Chad Dupuis) [950529 924804]
- [scsi] Revert: qla2xxx: Avoid losing any fc ports when loop id's are exhausted (Chad Dupuis) [950529 924804]
- [fs] defer do_filp_open() access checks to may_open() (Eric Sandeen) [928683 920752]
- [md] dm thin: bump the target version numbers (Mike Snitzer) [924823 922931]
- [md] dm-thin: fix discard corruption (Mike Snitzer) [924823 922931]
- [md] persistent-data: rename node to btree_node (Mike Snitzer) [924823 922931]
- [md] dm: fix limits initialization when there are no data devices (Mike Snitzer) [923096 908851]

[2.6.32-358.9.1]
- [fs] nfs: Fix handling of revoked delegations by setattr (Steve Dickson) [960415 952329]
- [fs] nfs: Return the delegation if the server returns NFS4ERR_OPENMODE (Steve Dickson) [960415 952329]
- [fs] nfs: Fix another potential state manager deadlock (Steve Dickson) [960436 950598]
- [fs] nfs: Fix another open/open_recovery deadlock (Steve Dickson) [960433 916806]
- [fs] nfs: Hold reference to layout hdr in layoutget (Steve Dickson) [960429 916726]
- [fs] nfs: add 'pnfs_' prefix to get_layout_hdr() and put_layout_hdr() (Steve Dickson) [960429 916726]
- [fs] nfs: nfs4_open_done first must check that GETATTR decoded a file type (Steve Dickson) [960412 916722]
- [net] sunrpc: Don't start the retransmission timer when out of socket space (Steve Dickson) [960426 916735]
- [fs] nfs: Don't use SetPageError in the NFS writeback code (Steve Dickson) [960420 912867]
- [fs] nfs: Don't decode skipped layoutgets (Steve Dickson) ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~358.11.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~358.11.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~358.11.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~358.11.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~358.11.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~358.11.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~358.11.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~358.11.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~358.11.1.el6", rls:"OracleLinux6"))) {
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

# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123733");
  script_cve_id("CVE-2012-4398", "CVE-2012-4461", "CVE-2012-4530");
  script_tag(name:"creation_date", value:"2015-10-06 11:07:50 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-0223)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0223");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0223.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2013-0223 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-279.22.1]
- [virt] kvm: invalid opcode oops on SET_SREGS with OSXSAVE bit set (Petr Matousek) [862903 862904] {CVE-2012-4461}
- [fs] fuse: optimize __fuse_direct_io() (Brian Foster) [865305 858850]
- [fs] fuse: optimize fuse_get_user_pages() (Brian Foster) [865305 858850]
- [fs] fuse: use get_user_pages_fast() (Brian Foster) [865305 858850]
- [fs] fuse: pass iov[] to fuse_get_user_pages() (Brian Foster) [865305 858850]
- [fs] mm: minor cleanup of iov_iter_single_seg_count() (Brian Foster) [865305 858850]
- [fs] fuse: use req->page_descs[] for argpages cases (Brian Foster) [865305 858850]
to fuse_req (Brian Foster) [865305 858850]
- [fs] fuse: rework fuse_do_ioctl() (Brian Foster) [865305 858850]
- [fs] fuse: rework fuse_perform_write() (Brian Foster) [865305 858850]
- [fs] fuse: rework fuse_readpages() (Brian Foster) [865305 858850]
- [fs] fuse: categorize fuse_get_req() (Brian Foster) [865305 858850]
- [fs] fuse: general infrastructure for pages[] of variable size (Brian Foster) [865305 858850]
- [fs] exec: do not leave bprm->interp on stack (Josh Poimboeuf) [880145 880146] {CVE-2012-4530}
- [fs] exec: use -ELOOP for max recursion depth (Josh Poimboeuf) [880145 880146] {CVE-2012-4530}
- [scsi] have scsi_internal_device_unblock take new state (Frantisek Hrbata) [878774 854140]
- [scsi] add new SDEV_TRANSPORT_OFFLINE state (Chris Leech) [878774 854140]
- [kernel] cpu: fix cpu_chain section mismatch (Frederic Weisbecker) [876090 852148]
- [kernel] sched: Don't modify cpusets during suspend/resume (Frederic Weisbecker) [876090 852148]
- [kernel] sched, cpuset: Drop __cpuexit from cpu hotplug callbacks (Frederic Weisbecker) [876090 852148]
- [kernel] sched: adjust when cpu_active and cpuset configurations are updated during cpu on/offlining (Frantisek Hrbata) [876090 852148]
- [kernel] cpu: return better errno on cpu hotplug failure (Frederic Weisbecker) [876090 852148]
- [kernel] cpu: introduce cpu_notify(), __cpu_notify(), cpu_notify_nofail() (Frederic Weisbecker) [876090 852148]
- [fs] nfs: Properly handle the case where the delegation is revoked (Steve Dickson) [846840 842435]
- [fs] nfs: Move cl_delegations to the nfs_server struct (Steve Dickson) [846840 842435]
- [fs] nfs: Introduce nfs_detach_delegations() (Steve Dickson) [846840 842435]
- [fs] nfs: Fix a number of RCU issues in the NFSv4 delegation code (Steve Dickson) [846840 842435]

[2.6.32-279.21.1]
- [scsi] mpt2sas: fix for driver fails EEH recovery from injected pci bus error (Tomas Henzl) [888818 829149]
- [net] bonding: Bonding driver does not consider the gso_max_size setting of slave devices (Ivan Vecera) [886618 883643]
- [netdrv] tg3: Do not set TSS for 5719 and 5720 (John Feeney) [888215 823371]
- [kernel] kmod: make __request_module() killable (Oleg Nesterov) [858755 819529] {CVE-2012-4398}
- [kernel] kmod: introduce call_modprobe() helper (Oleg Nesterov) [858755 819529] {CVE-2012-4398}
- ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~279.22.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~279.22.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~279.22.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~279.22.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~279.22.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~279.22.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~279.22.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~279.22.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~279.22.1.el6", rls:"OracleLinux6"))) {
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

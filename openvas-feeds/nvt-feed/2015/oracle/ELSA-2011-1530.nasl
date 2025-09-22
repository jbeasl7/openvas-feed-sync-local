# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122034");
  script_cve_id("CVE-2011-1020", "CVE-2011-3347", "CVE-2011-3638", "CVE-2011-4110");
  script_tag(name:"creation_date", value:"2015-10-06 11:11:59 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2011-1530)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-1530");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-1530.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2011-1530 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-220.el6]
- [drm] i915: fix unmap race condition introduced with VT-d fix (Dave Airlie) [750583]
- [scsi] iscsi: revert lockless queuecommand dispatch (Rob Evers) [751426]

[2.6.32-219.el6]
- [kernel] KEYS: Fix a NULL pointer deref in the user-defined key type (David Howells) [751190] {CVE-2011-4110}
- [scsi] fc class: fix building of Fibre Channel DUP drivers in 6.2 (Mike Christie) [750268]
- [fs] nfs: don't call __mark_inode_dirty while holding i_lock (Steve Dickson) [747391]
- [netdrv] vxge: allow rebinding the driver with a different number of SR-IOV VFs (Michal Schmidt) [694742]
- [netdrv] vxge: fix crash of VF when unloading PF (Michal Schmidt) [694742]
- [ata] revert libata: remove SCSI host lock (David Milburn) [751426]
- [crypto] ansi_cprng: enforce key != seed in fips mode (Jarod Wilson) [751198]
- [net] mac80211: Fix reassociation processing within ESS roaming (John Linville) [750350]
- [net] nl80211: Allow association to change channels during reassociation (John Linville) [750350]
- [net] mac80211: let cfg80211 manage auth state (John Linville) [750350]
- [net] cfg80211: avoid sending spurious deauth to userspace (John Linville) [750350]
- [net] mac80211: recalculate idle later in MLME (John Linville) [750350]
- [net] mac80211: avoid spurious deauth frames/messages (John Linville) [750350]
- [net] cfg80211: Allow reassociation in associated state (John Linville) [750350]
- [net] cfg80211: remove warning in deauth case (John Linville) [750350]
- [net] netfilter: fix nf_conntrack refcount leak in l4proto->error() (Thomas Graf) [745472]
- [scsi] qla2xxx: Remove check for null fcport from host reset handler (Chad Dupuis) [744741]
- [scsi] qla2xxx: Perform implicit logout during rport tear-down (Chad Dupuis) [744741]
- [scsi] Revert 'qla2xxx: Remove host_lock in queuecommand function' (Chad Dupuis) [744741]
- [drm] nv50/disp: shutdown display on suspend/hibernate (Ben Skeggs) [740857]
- [edac] Add sb_edac driver into the Red Hat Building system (Mauro Carvalho Chehab) [647700]
- [edac] Fix incorrect edac mode reporting in sb_edac (Mauro Carvalho Chehab) [647700]
- [edac] Add an experimental new driver to support Sandy Bridge CPUs (Mauro Carvalho Chehab) [647700]

[2.6.32-218.el6]
- [netdrv] benet: remove bogus 'unlikely' on vlan check (Ivan Vecera) [736429] {CVE-2011-3347}
- [netdrv] be2net: non-member vlan pkts not received in promiscuous mode (Ivan Vecera) [736429] {CVE-2011-3347}
- [netdrv] be2net: fix crash receiving non-member VLAN packets (Ivan Vecera) [736429] {CVE-2011-3347}
- [mm] fix race between mremap and removing migration entry (Andrea Arcangeli) [751084]

[2.6.32-217.el6]
- [fs] GFS2: rewrite fallocate code to write blocks directly (Benjamin Marzinski) [750208] {CVE-2011-4098}
- [netdrv] bnx2x: link fixes for 57810 (Andy Gospodarek) [749421]
- [netdrv] enic: fix accidental GRO off by default (Stefan Assmann) [749390]
- [scsi] qla2xxx: Correct ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~220.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~220.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~220.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~220.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~220.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~220.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~220.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~220.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~220.el6", rls:"OracleLinux6"))) {
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

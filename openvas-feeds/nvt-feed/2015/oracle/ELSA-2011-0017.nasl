# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122281");
  script_cve_id("CVE-2010-3296", "CVE-2010-3877", "CVE-2010-4072", "CVE-2010-4073", "CVE-2010-4075", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4158", "CVE-2010-4238", "CVE-2010-4243", "CVE-2010-4255", "CVE-2010-4263", "CVE-2010-4343");
  script_tag(name:"creation_date", value:"2015-10-06 11:15:54 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 16:35:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2011-0017)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0017");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0017.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-238.el5, oracleasm-2.6.18-238.el5' package(s) announced via the ELSA-2011-0017 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-238.el5]
- [net] bnx2: remove extra call to pci_map_page (John Feeney) [663509]
- [fs] nfs: set lock_context field in nfs_readpage_sync (Jeff Layton) [663853]

[2.6.18-237.el5]
- [block] fully zeroize request struct in rq_init (Rob Evers) [662154]
- [scsi] qla4xxx: update to 5.02.04.02.05.06-d0 (Chad Dupuis) [656999]
- [scsi] qla4xxx: make get_sys_info function return void (Chad Dupuis) [656999]
- [scsi] qla4xxx: don't default device to FAILED state (Chad Dupuis) [656999]
- [scsi] qla4xxx: mask bits in F/W Options during init (Chad Dupuis) [656999]
- [scsi] qla4xxx: update to 5.02.04.01.05.06-d0 (Chad Dupuis) [661768]
- [scsi] qla4xxx: disable irq instead of req pci_slot_reset (Chad Dupuis) [661768]
- [scsi] qla4xxx: no device add until scsi_add_host success (Chad Dupuis) [661768]
- [fs] nfs: set lock_context field in nfs_writepage_sync (Jeff Layton) [660580]
- [scsi] bfa: fix crash reading driver sysfs statistics (Rob Evers) [659880] {CVE-2010-4343}
- [misc] cpufeature: avoid corrupting cpuid vendor id (Matthew Garrett) [568751]
- [char] drm: don't set signal blocker on master process (Dave Airlie) [570604]
- [fs] nfs: remove problematic calls to nfs_clear_request (Jeff Layton) [656492]
- [fs] nfs: handle alloc failures in nfs_create_request (Jeff Layton) [656492]
- [fs] nfs: clean up nfs_create_request (Jeff Layton) [656492]
- [net] forcedeth: fix race condition in latest backport (Ivan Vecera) [658434]
- [net] cxgb3: fix read of uninitialized stack memory (Jay Fenlason) [633155] {CVE-2010-3296}
- [net] tg3: increase jumbo flag threshold (John Feeney) [660506]
- [net] s2io: fix netdev initialization failure (Bob Picco) [654948]
- [net] igb: only use vlan_gro_receive if vlans registered (Stefan Assmann) [660190] {CVE-2010-4263}
- [net] ipv6: try all routers with unknown reachable state (Thomas Graf) [661393]
- [misc] kernel: fix address limit override in OOPS path (Dave Anderson) [659571] {CVE-2010-4258}

[2.6.18-236.el5]
- [powerpc] support DLPAR remove operations (Steve Best) [655089]
- [net] igb: fix tx packet count (Stefan Assmann) [658801]
- [usb] serial: new driver MosChip MCS7840 (Stefan Assmann) [574507]
- [fs] exec: copy fixes into compat_do_execve paths (Oleg Nesterov) [625694] {CVE-2010-4243}
- [fs] exec: make argv/envp memory visible to oom-killer (Oleg Nesterov) [625694] {CVE-2010-4243}
- [misc] binfmts: kill bprm->argv_len (Oleg Nesterov) [625694] {CVE-2010-4243}
- [mm] backport upstream stack guard page /proc reporting (Larry Woodman) [643426]
- [mm] add guard page for stacks that grow upwards (Johannes Weiner) [630563]
- [net] tipc: fix information leak to userland (Jiri Pirko) [649892] {CVE-2010-3877}
- [sound] ALSA: fix sysfs unload and OSS mixer mutex issues (Jaroslav Kysela) [652165]
- [net] tg3: fix 5719 bugs (John Feeney) [657097]
- [net] bnx2: update firmware to 6.0.x (John Feeney) [644438]
- [redhat] configs: add ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-238.el5, oracleasm-2.6.18-238.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~238.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~238.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~238.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~238.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~238.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~238.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~238.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~238.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~238.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~238.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-238.el5", rpm:"ocfs2-2.6.18-238.el5~1.4.8~2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-238.el5PAE", rpm:"ocfs2-2.6.18-238.el5PAE~1.4.8~2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-238.el5debug", rpm:"ocfs2-2.6.18-238.el5debug~1.4.8~2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-238.el5xen", rpm:"ocfs2-2.6.18-238.el5xen~1.4.8~2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-238.el5", rpm:"oracleasm-2.6.18-238.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-238.el5PAE", rpm:"oracleasm-2.6.18-238.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-238.el5debug", rpm:"oracleasm-2.6.18-238.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-238.el5xen", rpm:"oracleasm-2.6.18-238.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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

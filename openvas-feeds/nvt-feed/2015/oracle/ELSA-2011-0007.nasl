# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122244");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2010-2492", "CVE-2010-2803", "CVE-2010-2955", "CVE-2010-2962", "CVE-2010-3067", "CVE-2010-3078", "CVE-2010-3079", "CVE-2010-3080", "CVE-2010-3081", "CVE-2010-3084", "CVE-2010-3298", "CVE-2010-3301", "CVE-2010-3432", "CVE-2010-3437", "CVE-2010-3442", "CVE-2010-3477", "CVE-2010-3698", "CVE-2010-3705", "CVE-2010-3861", "CVE-2010-3865", "CVE-2010-3874", "CVE-2010-3876", "CVE-2010-3880", "CVE-2010-3904", "CVE-2010-4072", "CVE-2010-4073", "CVE-2010-4074", "CVE-2010-4075", "CVE-2010-4077", "CVE-2010-4079", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4082", "CVE-2010-4083", "CVE-2010-4158", "CVE-2010-4160", "CVE-2010-4162", "CVE-2010-4163", "CVE-2010-4242", "CVE-2010-4248", "CVE-2010-4249", "CVE-2010-4263", "CVE-2010-4525", "CVE-2010-4668");
  script_tag(name:"creation_date", value:"2015-10-06 11:15:22 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-22T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-22 05:38:11 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-11 14:43:00 +0000 (Tue, 11 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2011-0007)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0007");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0007.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2011-0007 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-71.14.1.0.1.el6]
- replace Red Hat with Oracle in files genkey and kernel.spec

[2.6.32-71.14.1.el6]
- [kvm] x86: zero kvm_vcpu_events->interrupt.pad (Marcelo Tosatti) [665471 665409] {CVE-2010-4525}

[2.6.32-71.13.1.el6]
email_6.RHSA-2011-0007 178L, 11970C written
- [scsi] lpfc: Fixed crashes for NULL pnode dereference (Rob Evers) [660589 635733]

[2.6.32-71.12.1.el6]
- [netdrv] igb: only use vlan_gro_receive if vlans are registered (Stefan Assmann) [652804 660192] {CVE-2010-4263}
- [net] core: neighbour update Oops (Jiri Pirko) [660591 658518]
- [scsi] lpfc: Set heartbeat timer off by default (Rob Evers) [660244 655935]
- [scsi] lpfc: Fixed crashes for BUG_ONs hit in the lpfc_abort_handler (Rob Evers) [659611 645882]

[2.6.32-71.11.1.el6]
- [kernel] posix-cpu-timers: workaround to suppress the problems with mt exec (Oleg Nesterov) [656267 656268] {CVE-2010-4248}
- [fs] bio: take care not overflow page count when mapping/copying user data (Danny Feng) [652530 652531] {CVE-2010-4162}
- [net] can-bcm: fix minor heap overflow (Danny Feng) [651846 651847] {CVE-2010-3874}
- [net] filter: make sure filters don't read uninitialized memory (Jiri Pirko) [651704 651705] {CVE-2010-4158}
- [net] inet_diag: Make sure we actually run the same bytecode we audited (Jiri Pirko) [651268 651269] {CVE-2010-3880}
- [v4l] ivtvfb: prevent reading uninitialized stack memory (Mauro Carvalho Chehab) [648832 648833] {CVE-2010-4079}
- [drm] via/ioctl.c: prevent reading uninitialized stack memory (Dave Airlie) [648718 648719] {CVE-2010-4082}
- [char] nozomi: clear data before returning to userspace on TIOCGICOUNT (Mauro Carvalho Chehab) [648705 648706] {CVE-2010-4077}
- [serial] clean data before filling it on TIOCGICOUNT (Mauro Carvalho Chehab) [648702 648703] {CVE-2010-4075}
- [net] af_unix: limit unix_tot_inflight (Neil Horman) [656761 656762] {CVE-2010-4249}
- [block] check for proper length of iov entries in blk_rq_map_user_iov() (Danny Feng) [652958 652959] {CVE-2010-4163}
- [net] Limit sendto()/recvfrom()/iovec total length to INT_MAX (Jiri Pirko) [651894 651895] {CVE-2010-4160}
- [netdrv] mlx4: Add OFED-1.5.2 patch to increase log_mtts_per_seg (Jay Fenlason) [643815 637284]
- [kernel] kbuild: fix external module compiling (Aristeu Rozanski) [658879 655231]
- [net] bluetooth: Fix missing NULL check (Jarod Wilson) [655667 655668] {CVE-2010-4242}
- [kernel] ipc: initialize structure memory to zero for compat functions (Danny Feng) [648694 648695] {CVE-2010-4073}
- [kernel] shm: fix information leak to userland (Danny Feng) [648688 648689] {CVE-2010-4072}
- [md] dm: remove extra locking when changing device size (Mike Snitzer) [653900 644380]
- [block] read i_size with i_size_read() (Mike Snitzer) [653900 644380]
- [kbuild] don't sign out-of-tree modules (Aristeu Rozanski) [655122 653507]

[2.6.32-71.10.1.el6]
- [fs] xfs: prevent reading uninitialized stack memory (Dave Chinner) [630808 ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~71.14.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~71.14.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~71.14.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~71.14.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~71.14.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~71.14.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~71.14.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~71.14.1.el6", rls:"OracleLinux6"))) {
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

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1220.1");
  script_cve_id("CVE-2017-0861", "CVE-2017-11089", "CVE-2017-13220", "CVE-2017-18203", "CVE-2018-10087", "CVE-2018-10124", "CVE-2018-1087", "CVE-2018-7757", "CVE-2018-8781", "CVE-2018-8822", "CVE-2018-8897");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-20 14:00:15 +0000 (Wed, 20 Jun 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1220-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1220-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181220-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076537");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082299");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085331");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086194");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088147");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090643");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-May/003997.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:1220-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP1 LTSS kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2018-1087: And an unprivileged KVM guest user could use this flaw to potentially escalate their privileges inside a guest. (bsc#1087088)
- CVE-2018-8897: An unprivileged system user could use incorrect set up interrupt stacks to crash the Linux kernel resulting in DoS issue. (bsc#1087088)
- CVE-2018-8781: The udl_fb_mmap function in drivers/gpu/drm/udl/udl_fb.c had an integer-overflow vulnerability allowing local users with access to the udldrmfb driver to obtain full read and write permissions on kernel physical pages, resulting in a code execution in kernel space (bnc#1090643).
- CVE-2018-10124: The kill_something_info function in kernel/signal.c might allow local users to cause a denial of service via an INT_MIN argument (bnc#1089752).
- CVE-2018-10087: The kernel_wait4 function in kernel/exit.c in might allow local users to cause a denial of service by triggering an attempted use of the -INT_MIN value (bnc#1089608).
- CVE-2018-7757: Memory leak in the sas_smp_get_phy_events function in drivers/scsi/libsas/sas_expander.c allowed local users to cause a denial of service (memory consumption) via many read accesses to files in the /sys/class/sas_phy directory, as demonstrated by the /sys/class/sas_phy/phy-1:0:12/invalid_dword_count file (bnc#1084536).
- CVE-2017-13220: An elevation of privilege vulnerability in the Upstream kernel bluez was fixed. (bnc#1076537).
- CVE-2017-11089: A buffer overread is observed in nl80211_set_station when user space application sends attribute NL80211_ATTR_LOCAL_MESH_POWER_MODE with data of size less than 4 bytes (bnc#1088261).
- CVE-2017-0861: Use-after-free vulnerability in the snd_pcm_info function in the ALSA subsystem allowed attackers to gain privileges via unspecified vectors (bnc#1088260).
- CVE-2018-8822: Incorrect buffer length handling in the ncp_read_kernel function in fs/ncpfs/ncplib_kernel.c could be exploited by malicious NCPFS servers to crash the kernel or execute code (bnc#1086162).
- CVE-2017-18203: The dm_get_from_kobject function in drivers/md/dm.c allowed local users to cause a denial of service (BUG) by leveraging a race condition with __dm_destroy during creation and removal of DM devices (bnc#1083242).

The following non-security bugs were fixed:

- Integrate fixes resulting from bsc#1088147 More info in the respective commit messages.
- kabi: x86/kaiser: properly align trampoline stack (bsc#1087260).
- dcache: Add cond_resched in shrink_dentry_list (bsc#1086194).
- kGraft: fix small race in reversion code (bsc#1083125).
- kabi/severities: Ignore kgr_shadow_* kABI changes
- kvm/x86: fix icebp instruction handling (bsc#1087088).
- livepatch: Allow to call a custom callback when freeing shadow variables (bsc#1082299 fate#313296).
- livepatch: Initialize shadow variables ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.74~60.64.88.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.74~60.64.88.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.74~60.64.88.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.74~60.64.88.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.74~60.64.88.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.74~60.64.88.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.74~60.64.88.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.74~60.64.88.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.74~60.64.88.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.74~60.64.88.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.74~60.64.88.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.74~60.64.88.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.74~60.64.88.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.74~60.64.88.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.74~60.64.88.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.74~60.64.88.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.74~60.64.88.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_88-default", rpm:"kgraft-patch-3_12_74-60_64_88-default~1~2.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_88-xen", rpm:"kgraft-patch-3_12_74-60_64_88-xen~1~2.3.1", rls:"SLES12.0SP1"))) {
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

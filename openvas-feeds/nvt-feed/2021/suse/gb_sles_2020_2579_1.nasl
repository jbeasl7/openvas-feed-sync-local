# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2579.1");
  script_cve_id("CVE-2020-14386");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:54 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-22 18:24:17 +0000 (Tue, 22 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2579-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2579-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202579-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:2579-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP1 Azure kernel was updated to receive various security and bugfixes.

The following security bug was fixed:

CVE-2020-14386: Fixed a potential local privilege escalation via memory
 corruption (bsc#1176069).

The following non-security bugs were fixed:

EDAC: Fix reference count leaks (bsc#1112178).

KVM: SVM: fix svn_pin_memory()'s use of get_user_pages_fast()
 (bsc#1112178).

mm, vmstat: reduce zone->lock holding time by /proc/pagetypeinfo
 (bsc#1175691).

sched/deadline: Initialize ->dl_boosted (bsc#1112178).

scsi: lpfc: Add and rename a whole bunch of function parameter
 descriptions (bsc#1171558 bsc#1136666).

scsi: lpfc: Add description for lpfc_release_rpi()'s 'ndlpl param
 (bsc#1171558 bsc#1136666).

scsi: lpfc: Add missing misc_deregister() for lpfc_init() (bsc#1171558
 bsc#1136666).

scsi: lpfc: Ensure variable has the same stipulations as code using it
 (bsc#1171558 bsc#1136666).

scsi: lpfc: Fix a bunch of kerneldoc misdemeanors (bsc#1171558
 bsc#1136666).

scsi: lpfc: Fix FCoE speed reporting (bsc#1171558 bsc#1136666).

scsi: lpfc: Fix kerneldoc parameter formatting/misnaming/missing issues
 (bsc#1171558 bsc#1136666).

scsi: lpfc: Fix LUN loss after cable pull (bsc#1171558 bsc#1136666).

scsi: lpfc: Fix no message shown for lpfc_hdw_queue out of range value
 (bsc#1171558 bsc#1136666).

scsi: lpfc: Fix oops when unloading driver while running mds diags
 (bsc#1171558 bsc#1136666).

scsi: lpfc: Fix retry of PRLI when status indicates its unsupported
 (bsc#1171558 bsc#1136666).

scsi: lpfc: Fix RSCN timeout due to incorrect gidft counter (bsc#1171558
 bsc#1136666).

scsi: lpfc: Fix some function parameter descriptions (bsc#1171558
 bsc#1136666).

scsi: lpfc: Fix typo in comment for ULP (bsc#1171558 bsc#1136666).

scsi: lpfc: Fix-up around 120 documentation issues (bsc#1171558
 bsc#1136666).

scsi: lpfc: Fix-up formatting/docrot where appropriate (bsc#1171558
 bsc#1136666).

scsi: lpfc: Fix validation of bsg reply lengths (bsc#1171558
 bsc#1136666).

scsi: lpfc: NVMe remote port devloss_tmo from lldd (bsc#1171558
 bsc#1136666 bsc#1173060).

scsi: lpfc: nvmet: Avoid hang / use-after-free again when destroying
 targetport (bsc#1171558 bsc#1136666).

scsi: lpfc: Provide description for lpfc_mem_alloc()'s 'align' param
 (bsc#1171558 bsc#1136666).

scsi: lpfc: Quieten some printks (bsc#1171558 bsc#1136666).

scsi: lpfc: Remove unused variable 'pg_addr' (bsc#1171558 bsc#1136666).

scsi: lpfc: Update lpfc version to 12.8.0.3 (bsc#1171558 bsc#1136666).

scsi: lpfc: Use __printf() format notation (bsc#1171558 bsc#1136666).

x86/fsgsbase/64: Fix NULL deref in 86_fsgsbase_read_task (bsc#1112178).

x86/mce/inject: Fix a wrong assignment of i_mce.status (bsc#1112178).

x86/unwind/orc: Fix ORC for newly forked tasks (bsc#1058115).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~8.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~8.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~8.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~8.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~8.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~8.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~8.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~8.44.1", rls:"SLES15.0SP1"))) {
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

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1597.1");
  script_cve_id("CVE-2020-0543", "CVE-2020-10757", "CVE-2020-12114", "CVE-2020-12652", "CVE-2020-12653", "CVE-2020-12654", "CVE-2020-12656");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-18 00:28:12 +0000 (Thu, 18 Jun 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1597-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1597-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201597-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171098");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171218");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171219");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172317");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-June/006923.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:1597-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2020-0543: Fixed a side channel attack against special registers which could have resulted in leaking of read values to cores other than the one which called it.
 This attack is known as Special Register Buffer Data Sampling (SRBDS) or 'CrossTalk' (bsc#1154824).
- CVE-2020-12656: Fixed an improper handling of certain domain_release calls leadingch could have led to a memory leak (bsc#1171219).
- CVE-2020-12654: Fixed an issue in he wifi driver which could have allowed a remote AP to trigger a heap-based buffer overflow (bsc#1171202).
- CVE-2020-12653: Fixed an issue in the wifi driver which could have allowed local users to gain privileges or cause a denial of service (bsc#1171195).
- CVE-2020-12652: Fixed an issue which could have allowed local users to hold an incorrect lock during the ioctl operation and trigger a race condition (bsc#1171218).
- CVE-2020-12114: Fixed A pivot_root race condition which could have allowed local users to cause a denial of service (panic) by corrupting a mountpoint reference counter (bsc#1171098).
- CVE-2020-10757: Fixed an issue where remaping hugepage DAX to anon mmap could have caused user PTE access (bsc#1172317).

The following non-security bugs were fixed:

- can, slip: Protect tty->disc_data in write_wakeup and close with RCU (bsc#1171698).
- KEYS: allow reaching the keys quotas exactly (bsc#1171689).
- KEYS: reaching the keys quotas correctly (bsc#1171689).
- Revert 'ipc,sem: remove uneeded sem_undo_list lock usage in exit_sem()' (bsc#1172221).
- random: always use batched entropy for get_random_u{32,64} (bsc#1164871).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.121~92.135.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.121~92.135.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.121~92.135.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.121~92.135.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.121~92.135.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.121~92.135.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.121~92.135.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.121~92.135.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_135-default", rpm:"kgraft-patch-4_4_121-92_135-default~1~3.5.1", rls:"SLES12.0SP2"))) {
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

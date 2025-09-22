# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0756.1");
  script_cve_id("CVE-2016-10905", "CVE-2021-0920", "CVE-2022-0001", "CVE-2022-0002", "CVE-2022-0492", "CVE-2022-0617", "CVE-2022-24448");
  script_tag(name:"creation_date", value:"2022-03-09 04:10:18 +0000 (Wed, 09 Mar 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-15 13:35:37 +0000 (Tue, 15 Mar 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0756-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0756-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220756-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195543");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195939");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196079");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196612");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-March/010401.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:0756-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 kernel was updated to receive various security and bugfixes.


Transient execution side-channel attacks attacking the Branch History Buffer (BHB),
named 'Branch Target Injection' and 'Intra-Mode Branch History Injection' are now mitigated.

The following security bugs were fixed:

- CVE-2022-0001: Fixed Branch History Injection vulnerability (bsc#1191580).
- CVE-2022-0002: Fixed Intra-Mode Branch Target Injection vulnerability (bsc#1191580).
- CVE-2022-0617: Fixed a null pointer dereference in UDF file system functionality. A local user could crash the system by triggering udf_file_write_iter() via a malicious UDF image. (bsc#1196079)
- CVE-2022-0492: Fixed a privilege escalation related to cgroups v1 release_agent feature, which allowed bypassing namespace isolation unexpectedly (bsc#1195543).
- CVE-2022-24448: Fixed an issue in fs/nfs/dir.c. If an application sets the O_DIRECTORY flag, and tries to open a regular file, nfs_atomic_open() performs a regular lookup. If a regular file is found, ENOTDIR should have occurred, but the server instead returned uninitialized data in the file descriptor (bsc#1195612).
- CVE-2021-0920: Fixed a local privilege escalation due to a use-after-free bug in unix_gc (bsc#1193731).
- CVE-2016-10905: Fixed a use-after-free is gfs2_clear_rgrpd() and read_rindex_entry() (bsc#1146312).

The following non-security bug was fixed:

- net: sched: sch_teql: fix null-pointer dereference (bsc#1190717).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP2.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.121~92.169.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.121~92.169.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.121~92.169.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.121~92.169.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.121~92.169.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.121~92.169.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.121~92.169.1", rls:"SLES12.0SP2"))) {
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

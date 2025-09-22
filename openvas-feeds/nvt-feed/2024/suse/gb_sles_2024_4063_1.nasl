# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.4063.1");
  script_cve_id("CVE-2024-10976", "CVE-2024-10977", "CVE-2024-10978", "CVE-2024-10979");
  script_tag(name:"creation_date", value:"2024-11-27 04:17:38 +0000 (Wed, 27 Nov 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-11 21:27:49 +0000 (Tue, 11 Feb 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:4063-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4063-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20244063-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233325");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233326");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233327");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-November/019846.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/p-2910/");
  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/p-2936/");
  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/p-2955/");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/17/release-17.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/release/16.5/");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/release/16.6/");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/release/17.1/");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/release/17.2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql, postgresql16, postgresql17' package(s) announced via the SUSE-SU-2024:4063-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql, postgresql16, postgresql17 fixes the following issues:

This update ships postgresql17 , and fixes security issues with postgresql16:

- bsc#1230423: Relax the dependency of extensions on the server
 version from exact major.minor to greater or equal, after Tom
 Lane confirmed on the PostgreSQL packagers list that ABI
 stability is being taken care of between minor releases.

- bsc#1219340: The last fix was not correct. Improve it by removing
 the dependency again and call fillup only if it is installed.

postgresql16 was updated to 16.6:
* Repair ABI break for extensions that work with struct
 ResultRelInfo.
* Restore functionality of ALTER {ROLE<pipe>DATABASE} SET role.
* Fix cases where a logical replication slot's restart_lsn could
 go backwards.
* Avoid deleting still-needed WAL files during pg_rewind.
* Fix race conditions associated with dropping shared statistics
 entries.
* Count index scans in contrib/bloom indexes in the statistics
 views, such as the pg_stat_user_indexes.idx_scan counter.
* Fix crash when checking to see if an index's opclass options
 have changed.
* Avoid assertion failure caused by disconnected NFA sub-graphs
 in regular expression parsing.
* [link moved to references]

postgresql16 was updated to 16.5:

* CVE-2024-10976, bsc#1233323: Ensure cached plans are marked as
 dependent on the calling role when RLS applies to a
 non-top-level table reference.
* CVE-2024-10977, bsc#1233325: Make libpq discard error messages
 received during SSL or GSS protocol negotiation.
* CVE-2024-10978, bsc#1233326: Fix unintended interactions
 between SET SESSION AUTHORIZATION and SET ROLE
* CVE-2024-10979, bsc#1233327: Prevent trusted PL/Perl code from
 changing environment variables.
* [links moved to references]

- Don't build the libs and mini flavor anymore to hand over to
 PostgreSQL 17.

 * [link moved to references]

postgresql17 is shipped in version 17.2:

* CVE-2024-10976, bsc#1233323: Ensure cached plans are marked as
 dependent on the calling role when RLS applies to a
 non-top-level table reference.
* CVE-2024-10977, bsc#1233325: Make libpq discard error messages
 received during SSL or GSS protocol negotiation.
* CVE-2024-10978, bsc#1233326: Fix unintended interactions
 between SET SESSION AUTHORIZATION and SET ROLE
* CVE-2024-10979, bsc#1233327: Prevent trusted PL/Perl code from
 changing environment variables.
* [links moved to references]

Upgrade to 17.2:

* Repair ABI break for extensions that work with struct
 ResultRelInfo.
* Restore functionality of ALTER {ROLE<pipe>DATABASE} SET role.
* Fix cases where a logical replication slot's restart_lsn could
 go backwards.
* Avoid deleting still-needed WAL files during pg_rewind.
* Fix race conditions associated with dropping shared statistics
 entries.
* Count index scans in contrib/bloom indexes in the statistics
 views, such as the pg_stat_user_indexes.idx_scan ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'postgresql, postgresql16, postgresql17' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~17.2~150600.13.5.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-32bit", rpm:"libpq5-32bit~17.2~150600.13.5.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~17~150600.17.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16", rpm:"postgresql16~16.6~150600.16.10.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql17", rpm:"postgresql17~17.2~150600.13.5.1", rls:"SLES15.0SP6"))) {
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

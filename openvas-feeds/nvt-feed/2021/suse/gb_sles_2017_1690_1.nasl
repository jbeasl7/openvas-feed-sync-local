# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1690.1");
  script_cve_id("CVE-2017-7484", "CVE-2017-7485", "CVE-2017-7486");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-26 18:06:32 +0000 (Fri, 26 May 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1690-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1690-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171690-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037603");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038293");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-June/002981.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/9.4/static/release-9-4-10.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/9.4/static/release-9-4-11.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/9.4/static/release-9-4-12.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql94' package(s) announced via the SUSE-SU-2017:1690-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql94 to 9.4.12 fixes the following issues:

Upstream changelogs:

- [links moved to references]

Security issues fixed:

* CVE-2017-7486: Restrict visibility of
 pg_user_mappings.umoptions, to protect passwords stored as
 user mapping options. (bsc#1037624)

 Please note that manual action is needed to fix this in existing databases
 See the upstream release notes for details.
* CVE-2017-7485: recognize PGREQUIRESSL variable
 again. (bsc#1038293)
* CVE-2017-7484: Prevent exposure of statistical
 information via leaky operators. (bsc#1037603)

Changes in version 9.4.12:

* Build corruption with CREATE INDEX CONCURRENTLY
* Fixes for visibility and write-ahead-log stability

Changes in version 9.4.10:

* Fix WAL-logging of truncation of relation free space maps and
 visibility maps
* Fix incorrect creation of GIN index WAL records on big-endian
 machines
* Fix SELECT FOR UPDATE/SHARE to correctly lock tuples that have
 been updated by a subsequently-aborted transaction
* Fix EvalPlanQual rechecks involving CTE scans
* Fix improper repetition of previous results from hashed
 aggregation in a subquery

The libraries libpq and libecpg are now supplied by postgresql 9.6.");

  script_tag(name:"affected", value:"'postgresql94' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"postgresql94", rpm:"postgresql94~9.4.12~20.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-contrib", rpm:"postgresql94-contrib~9.4.12~20.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-docs", rpm:"postgresql94-docs~9.4.12~20.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-server", rpm:"postgresql94-server~9.4.12~20.1", rls:"SLES12.0SP2"))) {
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

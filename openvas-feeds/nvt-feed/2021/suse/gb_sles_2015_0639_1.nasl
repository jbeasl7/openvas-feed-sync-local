# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0639.1");
  script_cve_id("CVE-2014-8161", "CVE-2015-0241", "CVE-2015-0242", "CVE-2015-0243", "CVE-2015-0244");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:13 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-31 20:18:24 +0000 (Fri, 31 Jan 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0639-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0639-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150639-1.html");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/9.1/static/release-9-1-13.html");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/9.1/static/release-9-1-14.html");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/9.1/static/release-9-1-15.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916953");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-March/001321.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql91' package(s) announced via the SUSE-SU-2015:0639-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The PostgreSQL database server was updated to 9.1.15, fixing bugs and
security issues:

 * Fix buffer overruns in to_char() (CVE-2015-0241).
 * Fix buffer overrun in replacement *printf() functions
 (CVE-2015-0242).
 * Fix buffer overruns in contrib/pgcrypto (CVE-2015-0243).
 * Fix possible loss of frontend/backend protocol synchronization after
 an error (CVE-2015-0244).
 * Fix information leak via constraint-violation error messages
 (CVE-2014-8161).

For a comprehensive list of fixes, please refer to the following release
notes:

 * [link moved to references]
 <[link moved to references]>
 * [link moved to references]
 <[link moved to references]>
 * [link moved to references]
 <[link moved to references]>

Security Issues:

 * CVE-2015-0241
 <[link moved to references]>
 * CVE-2015-0243
 <[link moved to references]>
 * CVE-2015-0244
 <[link moved to references]>
 * CVE-2014-8161
 <[link moved to references]>");

  script_tag(name:"affected", value:"'postgresql91' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libecpg6", rpm:"libecpg6~9.1.15~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-32bit", rpm:"libpq5-32bit~9.1.15~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~9.1.15~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql91", rpm:"postgresql91~9.1.15~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql91-contrib", rpm:"postgresql91-contrib~9.1.15~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql91-docs", rpm:"postgresql91-docs~9.1.15~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql91-server", rpm:"postgresql91-server~9.1.15~0.3.1", rls:"SLES11.0SP3"))) {
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

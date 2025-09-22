# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120038");
  script_cve_id("CVE-2014-3580", "CVE-2014-8108");
  script_tag(name:"creation_date", value:"2015-09-08 11:15:53 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-555)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-555");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-555.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mod_dav_svn, subversion' package(s) announced via the ALAS-2015-555 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A NULL pointer dereference flaw was found in the way the mod_dav_svn module handled certain requests for URIs that trigger a lookup of a virtual transaction name. A remote, unauthenticated attacker could send a request for a virtual transaction name that does not exist, causing mod_dav_svn to crash. (CVE-2014-8108)

A NULL pointer dereference flaw was found in the way the mod_dav_svn module handled REPORT requests. A remote, unauthenticated attacker could use a specially crafted REPORT request to crash mod_dav_svn. (CVE-2014-3580)");

  script_tag(name:"affected", value:"'mod_dav_svn, subversion' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"mod24_dav_svn", rpm:"mod24_dav_svn~1.8.11~1.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_dav_svn", rpm:"mod_dav_svn~1.8.11~1.49.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_dav_svn-debuginfo", rpm:"mod_dav_svn-debuginfo~1.8.11~1.49.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion", rpm:"subversion~1.8.11~1.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-debuginfo", rpm:"subversion-debuginfo~1.8.11~1.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-devel", rpm:"subversion-devel~1.8.11~1.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-javahl", rpm:"subversion-javahl~1.8.11~1.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-libs", rpm:"subversion-libs~1.8.11~1.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-perl", rpm:"subversion-perl~1.8.11~1.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-python26", rpm:"subversion-python26~1.8.11~1.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-python27", rpm:"subversion-python27~1.8.11~1.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-ruby", rpm:"subversion-ruby~1.8.11~1.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-tools", rpm:"subversion-tools~1.8.11~1.50.amzn1", rls:"AMAZON"))) {
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

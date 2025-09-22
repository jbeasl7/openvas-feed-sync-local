# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120666");
  script_cve_id("CVE-2015-3184", "CVE-2015-3187", "CVE-2015-5259", "CVE-2015-5343");
  script_tag(name:"creation_date", value:"2016-03-31 05:02:09 +0000 (Thu, 31 Mar 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)");

  script_name("Amazon Linux: Security Advisory (ALAS-2016-676)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2016-676");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-676.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mod_dav_svn, subversion' package(s) announced via the ALAS-2016-676 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that when an SVN server (both svnserve and httpd with the mod_dav_svn module) searched the history of a file or a directory, it would disclose its location in the repository if that file or directory was not readable (for example, if it had been moved). (CVE-2015-3187)

An integer overflow was discovered allowing remote attackers to execute arbitrary code via an svn:// protocol string, which triggers a heap-based buffer overflow and an out-of-bounds read. (CVE-2015-5259)

It was found that the mod_authz_svn module did not properly restrict anonymous access to Subversion repositories under certain configurations when used with Apache httpd 2.4.x. This could allow a user to anonymously access files in a Subversion repository, which should only be accessible to authenticated users. (CVE-2015-3184)

It was found that the mod_dav_svn module was vulnerable to a remotely triggerable heap-based buffer overflow and out-of-bounds read caused by an integer overflow when parsing skel-encoded request bodies, allowing an attacker with write access to a repository to cause a denial of service attack (on 32-bit or 64-bit servers) or possibly execute arbitrary code (on 32-bit servers only) under the context of the httpd process. (CVE-2015-5343)");

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

  if(!isnull(res = isrpmvuln(pkg:"mod24_dav_svn", rpm:"mod24_dav_svn~1.8.15~1.54.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_dav_svn", rpm:"mod_dav_svn~1.8.15~1.52.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_dav_svn-debuginfo", rpm:"mod_dav_svn-debuginfo~1.8.15~1.52.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion", rpm:"subversion~1.8.15~1.54.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-debuginfo", rpm:"subversion-debuginfo~1.8.15~1.54.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-devel", rpm:"subversion-devel~1.8.15~1.54.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-javahl", rpm:"subversion-javahl~1.8.15~1.54.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-libs", rpm:"subversion-libs~1.8.15~1.54.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-perl", rpm:"subversion-perl~1.8.15~1.54.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-python26", rpm:"subversion-python26~1.8.15~1.54.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-python27", rpm:"subversion-python27~1.8.15~1.54.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-ruby", rpm:"subversion-ruby~1.8.15~1.54.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"subversion-tools", rpm:"subversion-tools~1.8.15~1.54.amzn1", rls:"AMAZON"))) {
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

# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120424");
  script_cve_id("CVE-2014-8080");
  script_tag(name:"creation_date", value:"2015-09-08 11:26:03 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2014-441)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2014-441");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-441.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby20' package(s) announced via the ALAS-2014-441 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The REXML parser in Ruby 1.9.x before 1.9.3-p550, 2.0.x before 2.0.0-p594, and 2.1.x before 2.1.4 allows remote attackers to cause a denial of service (memory consumption) via a crafted XML document, aka an XML Entity Expansion (XEE) attack.");

  script_tag(name:"affected", value:"'ruby20' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"ruby20", rpm:"ruby20~2.0.0.594~1.19.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby20-debuginfo", rpm:"ruby20-debuginfo~2.0.0.594~1.19.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby20-devel", rpm:"ruby20-devel~2.0.0.594~1.19.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby20-doc", rpm:"ruby20-doc~2.0.0.594~1.19.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby20-irb", rpm:"ruby20-irb~2.0.0.594~1.19.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby20-libs", rpm:"ruby20-libs~2.0.0.594~1.19.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem20-bigdecimal", rpm:"rubygem20-bigdecimal~1.2.0~1.19.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem20-io-console", rpm:"rubygem20-io-console~0.4.2~1.19.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem20-psych", rpm:"rubygem20-psych~2.0.0~1.19.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygems20", rpm:"rubygems20~2.0.14~1.19.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygems20-devel", rpm:"rubygems20-devel~2.0.14~1.19.amzn1", rls:"AMAZON"))) {
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

# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120094");
  script_cve_id("CVE-2013-1821");
  script_tag(name:"creation_date", value:"2015-09-08 11:17:17 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2013-195)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2013-195");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2013-195.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby19' package(s) announced via the ALAS-2013-195 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"lib/rexml/text.rb in the REXML parser in Ruby before 1.9.3-p392 allows remote attackers to cause a denial of service (memory consumption and crash) via crafted text nodes in an XML document, aka an XML Entity Expansion (XEE) attack.");

  script_tag(name:"affected", value:"'ruby19' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"ruby19", rpm:"ruby19~1.9.3.392~29.38.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby19-debuginfo", rpm:"ruby19-debuginfo~1.9.3.392~29.38.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby19-devel", rpm:"ruby19-devel~1.9.3.392~29.38.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby19-doc", rpm:"ruby19-doc~1.9.3.392~29.38.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby19-irb", rpm:"ruby19-irb~1.9.3.392~29.38.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby19-libs", rpm:"ruby19-libs~1.9.3.392~29.38.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem19-bigdecimal", rpm:"rubygem19-bigdecimal~1.1.0~29.38.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem19-io-console", rpm:"rubygem19-io-console~0.3~29.38.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem19-json", rpm:"rubygem19-json~1.5.5~29.38.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem19-minitest", rpm:"rubygem19-minitest~2.5.1~29.38.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem19-rake", rpm:"rubygem19-rake~0.9.2.2~29.38.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem19-rdoc", rpm:"rubygem19-rdoc~3.9.5~29.38.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygems19", rpm:"rubygems19~1.8.23~29.38.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygems19-devel", rpm:"rubygems19-devel~1.8.23~29.38.amzn1", rls:"AMAZON"))) {
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

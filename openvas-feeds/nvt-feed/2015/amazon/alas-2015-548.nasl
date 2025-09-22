# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120441");
  script_cve_id("CVE-2015-3900", "CVE-2015-4020");
  script_tag(name:"creation_date", value:"2015-09-08 11:26:30 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-548)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-548");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-548.html");
  script_xref(name:"URL", value:"https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2015-009/?fid=6478");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby21' package(s) announced via the ALAS-2015-548 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"RubyGems provides the ability of a domain to direct clients to a separate host that is used to fetch gems and make API calls against. This mechanism is implemented via DNS, specifically a SRV record _rubygems._tcp under the original requested domain. RubyGems did not validate the hostname returned in the SRV record before sending requests to it. (CVE-2015-3900)

As discussed upstream, CVE-2015-4020 is due to an incomplete fix for CVE-2015-3900, which allowed redirection to an arbitrary gem server in any security domain.");

  script_tag(name:"affected", value:"'ruby21' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"ruby21", rpm:"ruby21~2.1.6~1.17.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby21-debuginfo", rpm:"ruby21-debuginfo~2.1.6~1.17.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby21-devel", rpm:"ruby21-devel~2.1.6~1.17.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby21-doc", rpm:"ruby21-doc~2.1.6~1.17.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby21-irb", rpm:"ruby21-irb~2.1.6~1.17.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby21-libs", rpm:"ruby21-libs~2.1.6~1.17.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem21-bigdecimal", rpm:"rubygem21-bigdecimal~1.2.4~1.17.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem21-io-console", rpm:"rubygem21-io-console~0.4.3~1.17.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem21-psych", rpm:"rubygem21-psych~2.0.5~1.17.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygems21", rpm:"rubygems21~2.2.3~1.17.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygems21-devel", rpm:"rubygems21-devel~2.2.3~1.17.amzn1", rls:"AMAZON"))) {
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

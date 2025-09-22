# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120663");
  script_cve_id("CVE-2013-5588", "CVE-2013-5589", "CVE-2014-5025", "CVE-2014-5026", "CVE-2015-2665", "CVE-2015-4342", "CVE-2015-4454", "CVE-2015-4634", "CVE-2015-8377", "CVE-2015-8604");
  script_tag(name:"creation_date", value:"2016-03-31 05:02:06 +0000 (Thu, 31 Mar 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-22 01:29:00 +0000 (Fri, 22 Sep 2017)");

  script_name("Amazon Linux: Security Advisory (ALAS-2016-673)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2016-673");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-673.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cacti' package(s) announced via the ALAS-2016-673 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various cross-site scripting (XSS) flaws (CVE-2013-5588, CVE-2014-5025, CVE-2014-5026) and various SQL injection flaws (CVE-2013-5589, CVE-2015-4342, CVE-2015-4634, CVE-2015-8377, CVE-2015-8604) were discovered affecting versions of Cacti prior to 0.8.8g.

Cross-site scripting (XSS) vulnerability in Cacti before 0.8.8d allows remote attackers to inject arbitrary web script or HTML via unspecified vectors. (CVE-2015-2665)

SQL injection vulnerability in the get_hash_graph_template function in lib/functions.php in Cacti before 0.8.8d allows remote attackers to execute arbitrary SQL commands via the graph_template_id parameter to graph_templates.php. (CVE-2015-4454)");

  script_tag(name:"affected", value:"'cacti' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"cacti", rpm:"cacti~0.8.8g~7.6.amzn1", rls:"AMAZON"))) {
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

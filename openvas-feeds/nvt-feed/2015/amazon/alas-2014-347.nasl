# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120472");
  script_cve_id("CVE-2014-2326", "CVE-2014-2327", "CVE-2014-2328", "CVE-2014-2708", "CVE-2014-2709");
  script_tag(name:"creation_date", value:"2015-09-08 11:27:12 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2014-347)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2014-347");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-347.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cacti' package(s) announced via the ALAS-2014-347 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cross-site request forgery (CSRF) vulnerability in Cacti 0.8.7g, 0.8.8b, and earlier allows remote attackers to hijack the authentication of users for unspecified commands, as demonstrated by requests that (1) modify binary files, (2) modify configurations, or (3) add arbitrary users.

Cross-site scripting (XSS) vulnerability in cdef.php in Cacti 0.8.7g, 0.8.8b, and earlier allows remote attackers to inject arbitrary web script or HTML via unspecified vectors.

lib/rrd.php in Cacti 0.8.7g, 0.8.8b, and earlier allows remote attackers to execute arbitrary commands via shell metacharacters in unspecified parameters.

Multiple SQL injection vulnerabilities in graph_xport.php in Cacti 0.8.7g, 0.8.8b, and earlier allow remote attackers to execute arbitrary SQL commands via the (1) graph_start, (2) graph_end, (3) graph_height, (4) graph_width, (5) graph_nolegend, (6) print_source, (7) local_graph_id, or (8) rra_id parameter.

lib/graph_export.php in Cacti 0.8.7g, 0.8.8b, and earlier allows remote authenticated users to execute arbitrary commands via shell metacharacters in unspecified vectors.");

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

  if(!isnull(res = isrpmvuln(pkg:"cacti", rpm:"cacti~0.8.8b~5.4.amzn1", rls:"AMAZON"))) {
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

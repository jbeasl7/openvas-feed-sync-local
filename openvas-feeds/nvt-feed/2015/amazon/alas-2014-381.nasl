# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120403");
  script_cve_id("CVE-2014-4002");
  script_tag(name:"creation_date", value:"2015-09-08 11:25:34 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Amazon Linux: Security Advisory (ALAS-2014-381)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2014-381");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-381.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cacti' package(s) announced via the ALAS-2014-381 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple cross-site scripting (XSS) vulnerabilities in Cacti 0.8.8b allow remote attackers to inject arbitrary web script or HTML via the (1) drp_action parameter to cdef.php, (2) data_input.php, (3) data_queries.php, (4) data_sources.php, (5) data_templates.php, (6) graph_templates.php, (7) graphs.php, (8) host.php, or (9) host_templates.php or the (10) graph_template_input_id or (11) graph_template_id parameter to graph_templates_inputs.php.");

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

  if(!isnull(res = isrpmvuln(pkg:"cacti", rpm:"cacti~0.8.8b~7.5.amzn1", rls:"AMAZON"))) {
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

# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130073");
  script_cve_id("CVE-2015-2665", "CVE-2015-4342", "CVE-2015-4454", "CVE-2015-4634");
  script_tag(name:"creation_date", value:"2015-10-15 07:42:23 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0306)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(4|5)");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0306");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0306.html");
  script_xref(name:"URL", value:"http://www.cacti.net/release_notes_0_8_8d.php");
  script_xref(name:"URL", value:"http://www.cacti.net/release_notes_0_8_8e.php");
  script_xref(name:"URL", value:"http://www.cacti.net/release_notes_0_8_8f.php");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16202");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3295");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cacti' package(s) announced via the MGASA-2015-0306 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cross-site scripting (XSS) vulnerability in Cacti before 0.8.8d allows
remote attackers to inject arbitrary web script or HTML via unspecified
vectors (CVE-2015-2665).

SQL injection vulnerability in Cacti before 0.8.8d allows remote attackers
to execute arbitrary SQL commands via unspecified vectors involving a cdef
id (CVE-2015-4342).

SQL injection vulnerability in the get_hash_graph_template function in
lib/functions.php in Cacti before 0.8.8d allows remote attackers to
execute arbitrary SQL commands via the graph_template_id parameter to
graph_templates.php (CVE-2015-4454).

SQL injection vulnerability in Cacti before 0.8.8e in graphs.php
(CVE-2015-4634).

The cacti package has been updated to version 0.8.8e, which fixes this
issue, as well as other SQL injection and XSS issues and other bugs");

  script_tag(name:"affected", value:"'cacti' package(s) on Mageia 4, Mageia 5.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"cacti", rpm:"cacti~0.8.8f~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"cacti", rpm:"cacti~0.8.8f~1.mga5", rls:"MAGEIA5"))) {
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

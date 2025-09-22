# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0267");
  script_cve_id("CVE-2017-10970", "CVE-2017-11163", "CVE-2017-11691", "CVE-2017-12065", "CVE-2017-12066");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-02 17:47:07 +0000 (Wed, 02 Aug 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0267)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0267");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0267.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/07/27/1");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21242");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/7MRJCGVNDLW7RCTYSL72XGP74PCMOIH2/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/QN75M6HGIKEEX7HYFWHIO6IYDB5RXFP6/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2017-08/msg00018.html");
  script_xref(name:"URL", value:"https://www.cacti.net/changelog.php");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cacti' package(s) announced via the MGASA-2017-0267 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cross-site scripting (XSS) vulnerability in link.php in Cacti 1.1.12
allows remote anonymous users to inject arbitrary web script or HTML
via the id parameter, related to the die_html_input_error function in
lib/html_validate.php (CVE-2017-10970).

Cross-site scripting (XSS) vulnerability in aggregate_graphs.php in
Cacti 1.1.12 allows remote authenticated users to inject arbitrary web
script or HTML via specially crafted HTTP Referer headers, related to
the $cancel_url variable (CVE-2017-11163).

A Cross-site scripting vulnerability exists in cacti before 1.1.14 in
the user profile management page (auth_profile.php), allowing inject
arbitrary web script or HTML via specially crafted HTTP Referer headers
(CVE-2017-11691).

spikekill.php in Cacti before 1.1.16 might allow remote attackers to
execute arbitrary code via the avgnan, outlier-start, or outlier-end
parameter (CVE-2017-12065).

Cross-site scripting (XSS) vulnerability in aggregate_graphs.php in
Cacti before 1.1.16 allows remote authenticated users to inject
arbitrary web script or HTML via specially crafted HTTP Referer headers,
related to the $cancel_url variable (CVE-2017-12066).");

  script_tag(name:"affected", value:"'cacti' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"cacti", rpm:"cacti~1.1.16~1.mga6", rls:"MAGEIA6"))) {
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

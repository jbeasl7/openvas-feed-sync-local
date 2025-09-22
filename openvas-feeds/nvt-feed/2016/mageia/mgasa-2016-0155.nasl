# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131295");
  script_cve_id("CVE-2015-8864", "CVE-2016-4069");
  script_tag(name:"creation_date", value:"2016-05-09 11:17:58 +0000 (Mon, 09 May 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-08-26 13:46:49 +0000 (Fri, 26 Aug 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0155)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0155");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0155.html");
  script_xref(name:"URL", value:"http://lists.roundcube.net/pipermail/users/2016-April/011299.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/04/23/4");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18257");
  script_xref(name:"URL", value:"https://github.com/roundcube/roundcubemail/releases/tag/1.0.9");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'roundcubemail' package(s) announced via the MGASA-2016-0155 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated roundcubemail packages fix security vulnerabilities:

More security issues in the DBMail driver for the password plugin, related to
CVE-2015-2181.

XSS issue in SVG images handling (CVE-2015-8864).

Lack of protection for attachment download URLs against CSRF (CVE-2016-4069).

The roundcubemail package has been updated to version 1.0.9, fixing these
issues and several other bugs.");

  script_tag(name:"affected", value:"'roundcubemail' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"roundcubemail", rpm:"roundcubemail~1.0.9~1.mga5", rls:"MAGEIA5"))) {
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

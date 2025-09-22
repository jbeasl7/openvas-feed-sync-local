# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131311");
  script_cve_id("CVE-2015-7802", "CVE-2016-2191");
  script_tag(name:"creation_date", value:"2016-05-09 11:18:13 +0000 (Mon, 09 May 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-15 19:34:25 +0000 (Fri, 15 Apr 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0135)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0135");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0135.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/04/04/2");
  script_xref(name:"URL", value:"http://optipng.sourceforge.net/history.txt");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16949");
  script_xref(name:"URL", value:"https://sourceforge.net/p/optipng/bugs/53/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'optipng' package(s) announced via the MGASA-2016-0135 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An updated optipng package fixes a number of bugs and security vulnerabilities.

CVE-2015-7802 - Buffer over-read issue
CVE-2016-2191 - An invalid write and segmentation fault may occur while
processing bitmap images");

  script_tag(name:"affected", value:"'optipng' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"optipng", rpm:"optipng~0.7.6~1.mga5", rls:"MAGEIA5"))) {
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

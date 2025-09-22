# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0220");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2013-0220)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0220");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0220.html");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2013-029/");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2013-030/");
  script_xref(name:"URL", value:"http://owncloud.org/changelog/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10763");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'owncloud' package(s) announced via the MGASA-2013-0220 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"XSS vulnerability in 'Share Interface' (oC-SA-2013-029).

Authentication bypass in 'user_webdavauth' (oC-SA-2013-030).

This update provides OwnCloud 5.0.9, which fixes these issues, as well as
several other bugs.");

  script_tag(name:"affected", value:"'owncloud' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"owncloud", rpm:"owncloud~5.0.9~1.mga3", rls:"MAGEIA3"))) {
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

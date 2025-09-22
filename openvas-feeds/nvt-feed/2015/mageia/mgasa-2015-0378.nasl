# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130013");
  script_cve_id("CVE-2015-6500", "CVE-2015-6670");
  script_tag(name:"creation_date", value:"2015-10-15 07:41:31 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:C");

  script_name("Mageia: Security Advisory (MGASA-2015-0378)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0378");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0378.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16771");
  script_xref(name:"URL", value:"https://owncloud.org/changelog/");
  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2015-014");
  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2015-015");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'owncloud' package(s) announced via the MGASA-2015-0378 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated owncloud package fixes security vulnerabilities:

In ownCloud before 8.0.6, due to an incorrect usage of an ownCloud internal
file system function the passed path to the file scanner was resolved
relatively. An authenticated adversary may thus be able to get a listing of
directories (but not the containing files) existing on the filesystem.
However, it is not possible to access any of these files (CVE-2015-6500).

In ownCloud before 8.0.6, due to not properly checking the ownership of an
calendar, an authenticated attacker is able to download calendars of other
users via the 'calid' GET parameter to export.php in /apps/calendar/
(CVE-2015-6670).

The owncloud package has been updated to version 8.0.8, which fixes these
issues, as well as other bugs and other not-yet-disclosed security issues.");

  script_tag(name:"affected", value:"'owncloud' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"owncloud", rpm:"owncloud~8.0.8~1.mga5", rls:"MAGEIA5"))) {
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

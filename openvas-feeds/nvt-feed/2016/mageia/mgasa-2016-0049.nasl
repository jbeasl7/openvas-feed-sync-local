# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131211");
  script_cve_id("CVE-2014-9762", "CVE-2014-9763", "CVE-2014-9764");
  script_tag(name:"creation_date", value:"2016-02-08 17:55:18 +0000 (Mon, 08 Feb 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-13 17:33:08 +0000 (Fri, 13 May 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0049)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0049");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0049.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/01/22/6");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17594");
  script_xref(name:"URL", value:"https://git.enlightenment.org/legacy/imlib2.git/tree/ChangeLog");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'imlib2' package(s) announced via the MGASA-2016-0049 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various issues in imlib before 1.4.7 in the GIF loader (CVE-2014-9762,
CVE-2014-9764) and PNM loader (CVE-2014-9763) could cause crashes.

The imlib2 package has been updated to version 1.4.7, fixing these issues
and several other bugs.");

  script_tag(name:"affected", value:"'imlib2' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"imlib2", rpm:"imlib2~1.4.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imlib2-data", rpm:"imlib2-data~1.4.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64imlib2-devel", rpm:"lib64imlib2-devel~1.4.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64imlib2_1", rpm:"lib64imlib2_1~1.4.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64imlib2_1-filters", rpm:"lib64imlib2_1-filters~1.4.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64imlib2_1-loaders", rpm:"lib64imlib2_1-loaders~1.4.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libimlib2-devel", rpm:"libimlib2-devel~1.4.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libimlib2_1", rpm:"libimlib2_1~1.4.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libimlib2_1-filters", rpm:"libimlib2_1-filters~1.4.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libimlib2_1-loaders", rpm:"libimlib2_1-loaders~1.4.7~1.mga5", rls:"MAGEIA5"))) {
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

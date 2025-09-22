# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0215");
  script_cve_id("CVE-2015-8877", "CVE-2016-5116");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-08-09 15:48:45 +0000 (Tue, 09 Aug 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0215)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0215");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0215.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/05/29/5");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18562");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3587");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgd' package(s) announced via the MGASA-2016-0215 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libgd packages fix security vulnerabilities:

The gdImageScaleTwoPass function in gd_interpolation.c in libgd before 2.2.0
uses inconsistent allocate and free approaches, which allows remote attackers
to cause a denial of service (memory consumption) via a crafted call, as
demonstrated by a call to the PHP imagescale function (CVE-2015-8877).

While creating an XBM image (imagexbm) with an user supplied name, libgd before
2.2.0 did not check the vsnprintf return value, so an application might trust
this length and read more memory than it should, causing a read-out-of
boundaries, leaking stack memory (CVE-2016-5116).");

  script_tag(name:"affected", value:"'libgd' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"gd-utils", rpm:"gd-utils~2.2.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gd-devel", rpm:"lib64gd-devel~2.2.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gd-static-devel", rpm:"lib64gd-static-devel~2.2.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gd3", rpm:"lib64gd3~2.2.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgd", rpm:"libgd~2.2.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgd-devel", rpm:"libgd-devel~2.2.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgd-static-devel", rpm:"libgd-static-devel~2.2.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgd3", rpm:"libgd3~2.2.1~1.2.mga5", rls:"MAGEIA5"))) {
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

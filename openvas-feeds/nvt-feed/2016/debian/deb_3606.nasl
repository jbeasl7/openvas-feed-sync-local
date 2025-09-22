# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703606");
  script_cve_id("CVE-2016-2175");
  script_tag(name:"creation_date", value:"2016-06-23 22:00:00 +0000 (Thu, 23 Jun 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-06-02 15:11:12 +0000 (Thu, 02 Jun 2016)");

  script_name("Debian: Security Advisory (DSA-3606-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3606-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3606-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3606");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libpdfbox-java' package(s) announced via the DSA-3606-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that pdfbox, a PDF library for Java, was susceptible to XML External Entity attacks.

For the stable distribution (jessie), this problem has been fixed in version 1:1.8.7+dfsg-1+deb8u1.

For the testing distribution (stretch), this problem has been fixed in version 1:1.8.12-1.

For the unstable distribution (sid), this problem has been fixed in version 1:1.8.12-1.

We recommend that you upgrade your libpdfbox-java packages.");

  script_tag(name:"affected", value:"'libpdfbox-java' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libfontbox-java", ver:"1:1.8.7+dfsg-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfontbox-java-doc", ver:"1:1.8.7+dfsg-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjempbox-java", ver:"1:1.8.7+dfsg-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjempbox-java-doc", ver:"1:1.8.7+dfsg-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpdfbox-java", ver:"1:1.8.7+dfsg-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpdfbox-java-doc", ver:"1:1.8.7+dfsg-1+deb8u1", rls:"DEB8"))) {
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

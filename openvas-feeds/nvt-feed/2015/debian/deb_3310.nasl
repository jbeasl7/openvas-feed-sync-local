# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703310");
  script_tag(name:"creation_date", value:"2015-07-18 22:00:00 +0000 (Sat, 18 Jul 2015)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-3310-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3310-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3310-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3310");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'freexl' package(s) announced via the DSA-3310-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that an integer overflow in freexl, a library to parse Microsoft Excel spreadsheets may result in denial of service if a malformed Excel file is opened.

For the oldstable distribution (wheezy), this problem has been fixed in version 1.0.0b-1+deb7u2.

For the stable distribution (jessie), this problem has been fixed in version 1.0.0g-1+deb8u2.

For the testing distribution (stretch), this problem has been fixed in version 1.0.2-1.

For the unstable distribution (sid), this problem has been fixed in version 1.0.2-1.

We recommend that you upgrade your freexl packages.");

  script_tag(name:"affected", value:"'freexl' package(s) on Debian 7, Debian 8.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libfreexl-dev", ver:"1.0.0b-1+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreexl1", ver:"1.0.0b-1+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreexl1-dbg", ver:"1.0.0b-1+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libfreexl-dev", ver:"1.0.0g-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreexl1", ver:"1.0.0g-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreexl1-dbg", ver:"1.0.0g-1+deb8u2", rls:"DEB8"))) {
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

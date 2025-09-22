# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703584");
  script_cve_id("CVE-2015-7558", "CVE-2016-4348");
  script_tag(name:"creation_date", value:"2016-05-18 22:00:00 +0000 (Wed, 18 May 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-20 17:27:21 +0000 (Fri, 20 May 2016)");

  script_name("Debian: Security Advisory (DSA-3584-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3584-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3584-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3584");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'librsvg' package(s) announced via the DSA-3584-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gustavo Grieco discovered several flaws in the way librsvg, a SAX-based renderer library for SVG files, parses SVG files with circular definitions. A remote attacker can take advantage of these flaws to cause an application using the librsvg library to crash.

For the stable distribution (jessie), these problems have been fixed in version 2.40.5-1+deb8u2.

For the testing distribution (stretch), these problems have been fixed in version 2.40.12-1.

For the unstable distribution (sid), these problems have been fixed in version 2.40.12-1.

We recommend that you upgrade your librsvg packages.");

  script_tag(name:"affected", value:"'librsvg' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-rsvg-2.0", ver:"2.40.5-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librsvg2-2", ver:"2.40.5-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librsvg2-bin", ver:"2.40.5-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librsvg2-common", ver:"2.40.5-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librsvg2-dbg", ver:"2.40.5-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librsvg2-dev", ver:"2.40.5-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librsvg2-doc", ver:"2.40.5-1+deb8u2", rls:"DEB8"))) {
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

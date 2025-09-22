# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703772");
  script_cve_id("CVE-2016-10164");
  script_tag(name:"creation_date", value:"2017-01-25 23:00:00 +0000 (Wed, 25 Jan 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-22 16:19:18 +0000 (Wed, 22 Feb 2017)");

  script_name("Debian: Security Advisory (DSA-3772-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3772-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3772-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3772");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxpm' package(s) announced via the DSA-3772-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tobias Stoeckmann discovered that the libXpm library contained two integer overflow flaws, leading to a heap out-of-bounds write, while parsing XPM extensions in a file. An attacker can provide a specially crafted XPM file that, when processed by an application using the libXpm library, would cause a denial-of-service against the application, or potentially, the execution of arbitrary code with the privileges of the user running the application.

For the stable distribution (jessie), this problem has been fixed in version 1:3.5.12-0+deb8u1. This update is based on a new upstream version of libxpm including additional bug fixes.

For the testing distribution (stretch) and the unstable distribution (sid), this problem has been fixed in version 1:3.5.12-1.

We recommend that you upgrade your libxpm packages.");

  script_tag(name:"affected", value:"'libxpm' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libxpm-dev", ver:"1:3.5.12-0+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxpm4", ver:"1:3.5.12-0+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxpm4-dbg", ver:"1:3.5.12-0+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xpmutils", ver:"1:3.5.12-0+deb8u1", rls:"DEB8"))) {
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

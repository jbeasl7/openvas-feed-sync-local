# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703525");
  script_cve_id("CVE-2014-9766");
  script_tag(name:"creation_date", value:"2016-03-21 23:00:00 +0000 (Mon, 21 Mar 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-15 12:23:54 +0000 (Fri, 15 Apr 2016)");

  script_name("Debian: Security Advisory (DSA-3525-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3525-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3525-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3525");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pixman' package(s) announced via the DSA-3525-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vincent LE GARREC discovered an integer overflow in pixman, a pixel-manipulation library for X and cairo. A remote attacker can exploit this flaw to cause an application using the pixman library to crash, or potentially, to execute arbitrary code with the privileges of the user running the application.

For the oldstable distribution (wheezy), this problem has been fixed in version 0.26.0-4+deb7u2.

For the stable distribution (jessie), the testing distribution (stretch) and the unstable distribution (sid), this problem was already fixed in version 0.32.6-1.

We recommend that you upgrade your pixman packages.");

  script_tag(name:"affected", value:"'pixman' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libpixman-1-0", ver:"0.26.0-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpixman-1-0-dbg", ver:"0.26.0-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpixman-1-0-udeb", ver:"0.26.0-4+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpixman-1-dev", ver:"0.26.0-4+deb7u2", rls:"DEB7"))) {
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

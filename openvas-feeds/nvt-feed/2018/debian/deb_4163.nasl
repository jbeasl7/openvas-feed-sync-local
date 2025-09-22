# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704163");
  script_cve_id("CVE-2018-0492");
  script_tag(name:"creation_date", value:"2018-04-01 22:00:00 +0000 (Sun, 01 Apr 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-21 13:01:01 +0000 (Mon, 21 May 2018)");

  script_name("Debian: Security Advisory (DSA-4163-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4163-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4163-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4163");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/beep");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'beep' package(s) announced via the DSA-4163-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a race condition in beep (if configured as setuid via debconf) allows local privilege escalation.

For the oldstable distribution (jessie), this problem has been fixed in version 1.3-3+deb8u1.

For the stable distribution (stretch), this problem has been fixed in version 1.3-4+deb9u1.

We recommend that you upgrade your beep packages.

For the detailed security status of beep please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'beep' package(s) on Debian 8, Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"beep", ver:"1.3-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"beep-udeb", ver:"1.3-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"beep", ver:"1.3-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"beep-udeb", ver:"1.3-4+deb9u1", rls:"DEB9"))) {
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

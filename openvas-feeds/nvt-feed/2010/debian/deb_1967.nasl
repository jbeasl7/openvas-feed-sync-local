# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66658");
  script_cve_id("CVE-2010-0012");
  script_tag(name:"creation_date", value:"2010-01-11 22:48:26 +0000 (Mon, 11 Jan 2010)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-26 17:46:53 +0000 (Fri, 26 Jan 2024)");

  script_name("Debian: Security Advisory (DSA-1967-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1967-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/DSA-1967-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1967");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'transmission' package(s) announced via the DSA-1967-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Rosenberg discovered that Transmission, a lightweight client for the Bittorrent filesharing protocol, performs insufficient sanitising of file names specified in .torrent files. This could lead to the overwrite of local files with the privileges of the user running Transmission if the user is tricked into opening a malicious torrent file.

For the stable distribution (lenny), this problem has been fixed in version 1.22-1+lenny2.

For the unstable distribution (sid), this problem has been fixed in version 1.77-1.

We recommend that you upgrade your transmission packages.");

  script_tag(name:"affected", value:"'transmission' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"transmission", ver:"1.22-1+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"transmission-cli", ver:"1.22-1+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"transmission-common", ver:"1.22-1+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"transmission-gtk", ver:"1.22-1+lenny2", rls:"DEB5"))) {
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

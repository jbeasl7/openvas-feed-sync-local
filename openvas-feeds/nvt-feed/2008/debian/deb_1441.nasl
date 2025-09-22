# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60074");
  script_cve_id("CVE-2007-6454");
  script_tag(name:"creation_date", value:"2008-01-17 22:23:47 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1441-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1441-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1441-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1441");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'peercast' package(s) announced via the DSA-1441-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Luigi Auriemma discovered that PeerCast, a P2P audio and video streaming server, is vulnerable to a heap overflow in the HTTP server code, which allows remote attackers to cause a denial of service and possibly execute arbitrary code via a long SOURCE request.

The old stable distribution (sarge) does not contain peercast.

For the stable distribution (etch), this problem has been fixed in version 0.1217.toots.20060314-1etch0.

For the unstable distribution (sid), this problem has been fixed in version 0.1218+svn20071220+2.

We recommend that you upgrade your peercast packages.");

  script_tag(name:"affected", value:"'peercast' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"libpeercast0", ver:"0.1217.toots.20060314-1etch0", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpeercast0-dev", ver:"0.1217.toots.20060314-1etch0", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"peercast", ver:"0.1217.toots.20060314-1etch0", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"peercast-handlers", ver:"0.1217.toots.20060314-1etch0", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"peercast-servent", ver:"0.1217.toots.20060314-1etch0", rls:"DEB4"))) {
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

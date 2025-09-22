# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63062");
  script_cve_id("CVE-2007-3372", "CVE-2008-5081");
  script_tag(name:"creation_date", value:"2008-12-29 21:42:24 +0000 (Mon, 29 Dec 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-1690-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1690-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1690-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1690");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'avahi' package(s) announced via the DSA-1690-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two denial of service conditions were discovered in avahi, a Multicast DNS implementation.

Huge Dias discovered that the avahi daemon aborts with an assert error if it encounters a UDP packet with source port 0 (CVE-2008-5081).

It was discovered that the avahi daemon aborts with an assert error if it receives an empty TXT record over D-Bus (CVE-2007-3372).

For the stable distribution (etch), these problems have been fixed in version 0.6.16-3etch2.

For the unstable distribution (sid), these problems have been fixed in version 0.6.23-3.

We recommend that you upgrade your avahi packages.");

  script_tag(name:"affected", value:"'avahi' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"avahi-autoipd", ver:"0.6.16-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"avahi-daemon", ver:"0.6.16-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"avahi-discover", ver:"0.6.16-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"avahi-dnsconfd", ver:"0.6.16-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"avahi-utils", ver:"0.6.16-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavahi-client-dev", ver:"0.6.16-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavahi-client3", ver:"0.6.16-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavahi-common-data", ver:"0.6.16-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavahi-common-dev", ver:"0.6.16-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavahi-common3", ver:"0.6.16-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavahi-compat-howl-dev", ver:"0.6.16-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavahi-compat-howl0", ver:"0.6.16-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavahi-compat-libdnssd-dev", ver:"0.6.16-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavahi-compat-libdnssd1", ver:"0.6.16-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavahi-core-dev", ver:"0.6.16-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavahi-core4", ver:"0.6.16-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavahi-glib-dev", ver:"0.6.16-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavahi-glib1", ver:"0.6.16-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavahi-qt3-1", ver:"0.6.16-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavahi-qt3-dev", ver:"0.6.16-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavahi-qt4-1", ver:"0.6.16-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavahi-qt4-dev", ver:"0.6.16-3etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-avahi", ver:"0.6.16-3etch2", rls:"DEB4"))) {
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

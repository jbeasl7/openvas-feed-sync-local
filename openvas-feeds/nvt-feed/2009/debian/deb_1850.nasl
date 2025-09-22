# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64562");
  script_cve_id("CVE-2009-1438", "CVE-2009-1513");
  script_tag(name:"creation_date", value:"2009-08-17 14:54:45 +0000 (Mon, 17 Aug 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1850-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1850-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1850-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1850");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libmodplug' package(s) announced via the DSA-1850-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in libmodplug, the shared libraries for mod music based on ModPlug. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-1438

It was discovered that libmodplug is prone to an integer overflow when processing a MED file with a crafted song comment or song name.

CVE-2009-1513

It was discovered that libmodplug is prone to a buffer overflow in the PATinst function, when processing a long instrument name.

For the oldstable distribution (etch), these problems have been fixed in version 1:0.7-5.2+etch1.

For the stable distribution (lenny), these problems have been fixed in version 1:0.8.4-1+lenny1.

For the testing distribution (squeeze) and the unstable distribution (sid), these problems have been fixed in version 1:0.8.7-1.

We recommend that you upgrade your libmodplug packages.");

  script_tag(name:"affected", value:"'libmodplug' package(s) on Debian 4, Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libmodplug-dev", ver:"1:0.7-5.2+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmodplug0c2", ver:"1:0.7-5.2+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"libmodplug-dev", ver:"1:0.8.4-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmodplug0c2", ver:"1:0.8.4-1+lenny1", rls:"DEB5"))) {
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

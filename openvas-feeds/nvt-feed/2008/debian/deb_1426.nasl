# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.59960");
  script_cve_id("CVE-2007-3388", "CVE-2007-4137");
  script_tag(name:"creation_date", value:"2008-01-17 22:23:47 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1426-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.1|4)");

  script_xref(name:"Advisory-ID", value:"DSA-1426-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1426-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1426");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qt-x11-free' package(s) announced via the DSA-1426-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local/remote vulnerabilities have been discovered in the Qt GUI library. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-3388

Tim Brown and Dirk Muller discovered several format string vulnerabilities in the handling of error messages, which might lead to the execution of arbitrary code.

CVE-2007-4137

Dirk Muller discovered an off-by-one buffer overflow in the Unicode handling, which might lead to the execution of arbitrary code.

For the old stable distribution (sarge), these problems have been fixed in version 3:3.3.4-3sarge3. Packages for m68k will be provided later.

For the stable distribution (etch), these problems have been fixed in version 3:3.3.7-4etch1.

For the unstable distribution (sid), these problems have been fixed in version 3:3.3.7-8.

We recommend that you upgrade your qt-x11-free packages.");

  script_tag(name:"affected", value:"'qt-x11-free' package(s) on Debian 3.1, Debian 4.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"libqt3-compat-headers", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3-dev", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3-headers", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3-i18n", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3-mt-dev", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3c102", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3c102-ibase", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3c102-mt", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3c102-mt-ibase", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3c102-mt-mysql", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3c102-mt-odbc", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3c102-mt-psql", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3c102-mt-sqlite", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3c102-mysql", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3c102-odbc", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3c102-psql", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3c102-sqlite", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt3-apps-dev", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt3-assistant", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt3-designer", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt3-dev-tools", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt3-dev-tools-compat", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt3-dev-tools-embedded", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt3-doc", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt3-examples", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt3-linguist", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt3-qtconfig", ver:"3:3.3.4-3sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"libqt3-compat-headers", ver:"3:3.3.7-4etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3-headers", ver:"3:3.3.7-4etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3-i18n", ver:"3:3.3.7-4etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3-mt", ver:"3:3.3.7-4etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3-mt-dev", ver:"3:3.3.7-4etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3-mt-ibase", ver:"3:3.3.7-4etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3-mt-mysql", ver:"3:3.3.7-4etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3-mt-odbc", ver:"3:3.3.7-4etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3-mt-psql", ver:"3:3.3.7-4etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt3-mt-sqlite", ver:"3:3.3.7-4etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt-x11-free-dbg", ver:"3:3.3.7-4etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt3-apps-dev", ver:"3:3.3.7-4etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt3-assistant", ver:"3:3.3.7-4etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt3-designer", ver:"3:3.3.7-4etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt3-dev-tools", ver:"3:3.3.7-4etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt3-dev-tools-compat", ver:"3:3.3.7-4etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt3-dev-tools-embedded", ver:"3:3.3.7-4etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt3-doc", ver:"3:3.3.7-4etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt3-examples", ver:"3:3.3.7-4etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt3-linguist", ver:"3:3.3.7-4etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt3-qtconfig", ver:"3:3.3.7-4etch1", rls:"DEB4"))) {
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

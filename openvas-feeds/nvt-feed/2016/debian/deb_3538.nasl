# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703538");
  script_cve_id("CVE-2015-8789", "CVE-2015-8790", "CVE-2015-8791");
  script_tag(name:"creation_date", value:"2016-03-30 22:00:00 +0000 (Wed, 30 Mar 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-02-08 23:01:17 +0000 (Mon, 08 Feb 2016)");

  script_name("Debian: Security Advisory (DSA-3538-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3538-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3538-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3538");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libebml' package(s) announced via the DSA-3538-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in libebml, a library for manipulating Extensible Binary Meta Language files.

CVE-2015-8789

Context-dependent attackers could trigger a use-after-free vulnerability by providing a maliciously crafted EBML document.

CVE-2015-8790

Context-dependent attackers could obtain sensitive information from the process' heap memory by using a maliciously crafted UTF-8 string.

CVE-2015-8791

Context-dependent attackers could obtain sensitive information from the process' heap memory by using a maliciously crafted length value in an EBML id.

For the oldstable distribution (wheezy), these problems have been fixed in version 1.2.2-2+deb7u1.

For the stable distribution (jessie), these problems have been fixed in version 1.3.0-2+deb8u1.

For the testing (stretch) and unstable (sid) distributions, these problems have been fixed in version 1.3.3-1.

We recommend that you upgrade your libebml packages.");

  script_tag(name:"affected", value:"'libebml' package(s) on Debian 7, Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libebml-dev", ver:"1.2.2-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libebml3", ver:"1.2.2-2+deb7u1", rls:"DEB7"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libebml-dev", ver:"1.3.0-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libebml4", ver:"1.3.0-2+deb8u1", rls:"DEB8"))) {
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

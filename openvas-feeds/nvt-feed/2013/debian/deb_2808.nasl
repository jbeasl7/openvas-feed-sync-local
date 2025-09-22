# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702808");
  script_cve_id("CVE-2013-1447", "CVE-2013-6045", "CVE-2013-6052", "CVE-2013-6054");
  script_tag(name:"creation_date", value:"2013-12-02 23:00:00 +0000 (Mon, 02 Dec 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2808-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2808-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/DSA-2808-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2808");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openjpeg' package(s) announced via the DSA-2808-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in OpenJPEG, a JPEG 2000 image library, that may lead to denial of service (CVE-2013-1447) via application crash or high memory consumption, possible code execution through heap buffer overflows (CVE-2013-6045), information disclosure (CVE-2013-6052), or yet another heap buffer overflow that only appears to affect OpenJPEG 1.3 (CVE-2013-6054).

For the oldstable distribution (squeeze), these problems have been fixed in version 1.3+dfsg-4+squeeze2.

For the stable distribution (wheezy), these problems have been fixed in version 1.3+dfsg-4.7.

For the testing distribution (jessie), and the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your openjpeg packages.");

  script_tag(name:"affected", value:"'openjpeg' package(s) on Debian 6, Debian 7.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpeg-dev", ver:"1.3+dfsg-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpeg2", ver:"1.3+dfsg-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpeg2-dbg", ver:"1.3+dfsg-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjpeg-tools", ver:"1.3+dfsg-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpeg-dev", ver:"1.3+dfsg-4.7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpeg-dev", ver:"1.3+dfsg-4.7+b1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpeg2", ver:"1.3+dfsg-4.7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpeg2", ver:"1.3+dfsg-4.7+b1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpeg2-dbg", ver:"1.3+dfsg-4.7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpeg2-dbg", ver:"1.3+dfsg-4.7+b1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjpeg-tools", ver:"1.3+dfsg-4.7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjpeg-tools", ver:"1.3+dfsg-4.7+b1", rls:"DEB7"))) {
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

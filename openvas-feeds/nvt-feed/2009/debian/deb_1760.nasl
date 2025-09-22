# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63732");
  script_cve_id("CVE-2008-4190", "CVE-2009-0790");
  script_tag(name:"creation_date", value:"2009-04-06 18:58:11 +0000 (Mon, 06 Apr 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-1760-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1760-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1760-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1760");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openswan' package(s) announced via the DSA-1760-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been discovered in openswan, an IPSec implementation for linux. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-4190

Dmitry E. Oboukhov discovered that the livetest tool is using temporary files insecurely, which could lead to a denial of service attack.

CVE-2009-0790

Gerd v. Egidy discovered that the Pluto IKE daemon in openswan is prone to a denial of service attack via a malicious packet.

For the oldstable distribution (etch), this problem has been fixed in version 2.4.6+dfsg.2-1.1+etch1.

For the stable distribution (lenny), this problem has been fixed in version 2.4.12+dfsg-1.3+lenny1.

For the testing distribution (squeeze) and the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your openswan packages.");

  script_tag(name:"affected", value:"'openswan' package(s) on Debian 4, Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-openswan", ver:"1:2.4.6+dfsg.2-1.1+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openswan", ver:"1:2.4.6+dfsg.2-1.1+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openswan-modules-source", ver:"1:2.4.6+dfsg.2-1.1+etch1", rls:"DEB4"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-openswan", ver:"1:2.4.12+dfsg-1.3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openswan", ver:"1:2.4.12+dfsg-1.3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openswan-modules-source", ver:"1:2.4.12+dfsg-1.3+lenny1", rls:"DEB5"))) {
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

# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64035");
  script_cve_id("CVE-2009-1755");
  script_tag(name:"creation_date", value:"2009-05-25 18:59:33 +0000 (Mon, 25 May 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-1803-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1803-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1803-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1803");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nsd, nsd3' package(s) announced via the DSA-1803-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ilja van Sprundel discovered that a buffer overflow in NSD, an authoritative name service daemon, allowed to crash the server by sending a crafted packet, creating a denial of service.

For the old stable distribution (etch), this problem has been fixed in version 2.3.6-1+etch1 of the nsd package.

For the stable distribution (lenny), this problem has been fixed in version 2.3.7-1.1+lenny1 of the nsd package and version 3.0.7-3.lenny2 of the nsd3 package.

For the unstable distribution (sid), this problem has been fixed in version 2.3.7-3 for nsd, nsd3 will be fixed soon.

We recommend that you upgrade your nsd or nsd3 package.");

  script_tag(name:"affected", value:"'nsd, nsd3' package(s) on Debian 4, Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"nsd", ver:"2.3.6-1+etch1", rls:"DEB4"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"nsd", ver:"2.3.7-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nsd3", ver:"3.0.7-3.lenny2", rls:"DEB5"))) {
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

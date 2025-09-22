# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.59639");
  script_cve_id("CVE-2007-6114", "CVE-2007-6117", "CVE-2007-6118", "CVE-2007-6120", "CVE-2007-6121");
  script_tag(name:"creation_date", value:"2008-01-17 22:23:47 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1414-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.1|4)");

  script_xref(name:"Advisory-ID", value:"DSA-1414-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1414-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1414");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ethereal, wireshark' package(s) announced via the DSA-1414-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Wireshark network traffic analyzer, which may lead to denial of service or execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-6114

Stefan Esser discovered a buffer overflow in the SSL dissector. Fabiodds discovered a buffer overflow in the iSeries trace dissector.

CVE-2007-6117

A programming error was discovered in the HTTP dissector, which may lead to denial of service.

CVE-2007-6118

The MEGACO dissector could be tricked into resource exhaustion.

CVE-2007-6120

The Bluetooth SDP dissector could be tricked into an endless loop.

CVE-2007-6121

The RPC portmap dissector could be tricked into dereferencing a NULL pointer.

For the old stable distribution (sarge), these problems have been fixed in version 0.10.10-2sarge10. (In Sarge Wireshark used to be called Ethereal). Updated packages for sparc and m68k will be provided later.

For the stable distribution (etch), these problems have been fixed in version 0.99.4-5.etch.1. Updated packages for sparc will be provided later.

We recommend that you upgrade your wireshark/ethereal packages.");

  script_tag(name:"affected", value:"'ethereal, wireshark' package(s) on Debian 3.1, Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ethereal", ver:"0.10.10-2sarge10", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ethereal-common", ver:"0.10.10-2sarge10", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ethereal-dev", ver:"0.10.10-2sarge10", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tethereal", ver:"0.10.10-2sarge10", rls:"DEB3.1"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ethereal", ver:"0.99.4-5.etch.1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ethereal-common", ver:"0.99.4-5.etch.1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ethereal-dev", ver:"0.99.4-5.etch.1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tethereal", ver:"0.99.4-5.etch.1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tshark", ver:"0.99.4-5.etch.1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark", ver:"0.99.4-5.etch.1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-common", ver:"0.99.4-5.etch.1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-dev", ver:"0.99.4-5.etch.1", rls:"DEB4"))) {
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

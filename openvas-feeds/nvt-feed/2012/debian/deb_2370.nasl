# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70689");
  script_cve_id("CVE-2011-4528", "CVE-2011-4869");
  script_tag(name:"creation_date", value:"2012-02-11 08:15:52 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-2370-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");

  script_xref(name:"Advisory-ID", value:"DSA-2370-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2370-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2370");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'unbound' package(s) announced via the DSA-2370-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Unbound, a recursive DNS resolver, would crash when processing certain malformed DNS responses from authoritative DNS servers, leading to denial of service.

CVE-2011-4528

Unbound attempts to free unallocated memory during processing of duplicate CNAME records in a signed zone.

CVE-2011-4869

Unbound does not properly process malformed responses which lack expected NSEC3 records.

For the oldstable distribution (lenny), these problems have been fixed in version 1.4.6-1~lenny2.

For the stable distribution (squeeze), these problems have been fixed in version 1.4.6-1+squeeze2.

For the testing distribution (wheezy) and the unstable distribution (sid), these problems have been fixed in version 1.4.14-1.

We recommend that you upgrade your unbound packages.");

  script_tag(name:"affected", value:"'unbound' package(s) on Debian 5, Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libunbound-dev", ver:"1.4.6-1~lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libunbound2", ver:"1.4.6-1~lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"unbound", ver:"1.4.6-1~lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"unbound-host", ver:"1.4.6-1~lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libunbound-dev", ver:"1.4.6-1+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libunbound2", ver:"1.4.6-1+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"unbound", ver:"1.4.6-1+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"unbound-host", ver:"1.4.6-1+squeeze2", rls:"DEB6"))) {
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

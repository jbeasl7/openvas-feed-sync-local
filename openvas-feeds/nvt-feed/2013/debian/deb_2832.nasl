# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702832");
  script_cve_id("CVE-2011-4971", "CVE-2013-7239");
  script_tag(name:"creation_date", value:"2013-12-31 23:00:00 +0000 (Tue, 31 Dec 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2832-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2832-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2832-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2832");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'memcached' package(s) announced via the DSA-2832-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in memcached, a high-performance memory object caching system. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2011-4971

Stefan Bucur reported that memcached could be caused to crash by sending a specially crafted packet.

CVE-2013-7239

It was reported that SASL authentication could be bypassed due to a flaw related to the management of the SASL authentication state. With a specially crafted request, a remote attacker may be able to authenticate with invalid SASL credentials.

For the oldstable distribution (squeeze), these problems have been fixed in version 1.4.5-1+deb6u1. Note that the patch for CVE-2013-7239 was not applied for the oldstable distribution as SASL support is not enabled in this version. This update also provides the fix for CVE-2013-0179 which was fixed for stable already.

For the stable distribution (wheezy), these problems have been fixed in version 1.4.13-0.2+deb7u1.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your memcached packages.");

  script_tag(name:"affected", value:"'memcached' package(s) on Debian 6, Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"memcached", ver:"1.4.5-1+deb6u1", rls:"DEB6"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"memcached", ver:"1.4.13-0.2+deb7u1", rls:"DEB7"))) {
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

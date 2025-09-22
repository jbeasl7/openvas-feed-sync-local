# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702937");
  script_cve_id("CVE-2014-0240", "CVE-2014-0242");
  script_tag(name:"creation_date", value:"2014-05-26 22:00:00 +0000 (Mon, 26 May 2014)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-17 17:22:07 +0000 (Tue, 17 Dec 2019)");

  script_name("Debian: Security Advisory (DSA-2937-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2937-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2937-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2937");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mod-wsgi' package(s) announced via the DSA-2937-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security issues have been found in the Python WSGI adapter module for Apache:

CVE-2014-0240

Robert Kisteleki discovered a potential privilege escalation in daemon mode. This is not exploitable with the kernel used in Debian 7.0/wheezy.

CVE-2014-0242

Buck Golemon discovered that incorrect memory handling could lead to information disclosure when processing Content-Type headers.

For the oldstable distribution (squeeze), these problems have been fixed in version 3.3-2+deb6u1.

For the stable distribution (wheezy), these problems have been fixed in version 3.3-4+deb7u1.

For the testing distribution (jessie), these problems have been fixed in version 3.5-1.

For the unstable distribution (sid), these problems have been fixed in version 3.5-1.

We recommend that you upgrade your mod-wsgi packages.");

  script_tag(name:"affected", value:"'mod-wsgi' package(s) on Debian 6, Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-wsgi", ver:"3.3-2+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-wsgi-py3", ver:"3.3-2+deb6u1", rls:"DEB6"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-wsgi", ver:"3.3-4+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-wsgi-py3", ver:"3.3-4+deb7u1", rls:"DEB7"))) {
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

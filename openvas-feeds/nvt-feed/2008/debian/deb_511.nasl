# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53201");
  script_version("2024-09-10T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-09-10 05:05:42 +0000 (Tue, 10 Sep 2024)");
  script_tag(name:"creation_date", value:"2008-01-17 22:45:44 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-0176", "CVE-2004-0365", "CVE-2004-0367");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2004-01-01 05:00:00 +0000 (Thu, 01 Jan 2004)");
  script_name("Debian Security Advisory DSA 511-1 (ethereal)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20511-1");
  script_tag(name:"insight", value:"Several buffer overflow vulnerabilities were discovered in ethereal, a
network traffic analyzer.  These vulnerabilities are described in the
ethereal advisory enpa-sa-00013.  Of these, only some parts of
CVE-2004-0176 affect the version of ethereal in Debian woody.
CVE-2004-0367 and CVE-2004-0365 are not applicable to this version.

For the current stable distribution (woody), these problems have been
fixed in version 0.9.4-1woody7.

For the unstable distribution (sid), these problems have been fixed in
version 0.10.3-1.

We recommend that you update your ethereal package.");
  script_tag(name:"summary", value:"The remote host is missing an update to ethereal
announced via advisory DSA 511-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"ethereal", ver:"0.9.4-1woody7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ethereal-common", ver:"0.9.4-1woody7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ethereal-dev", ver:"0.9.4-1woody7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tethereal", ver:"0.9.4-1woody7", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

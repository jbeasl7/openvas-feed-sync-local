# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55162");
  script_cve_id("CVE-2005-0989", "CVE-2005-1159", "CVE-2005-1160", "CVE-2005-1532", "CVE-2005-2261", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2269", "CVE-2005-2270");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-781-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-781-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-781-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-781");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mozilla-thunderbird' package(s) announced via the DSA-781-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several problems have been discovered in Mozilla Thunderbird, the standalone mail client of the Mozilla suite. The Common Vulnerabilities and Exposures project identifies the following problems:

CAN-2005-0989

Remote attackers could read portions of heap memory into a Javascript string via the lambda replace method.

CAN-2005-1159

The Javascript interpreter could be tricked to continue execution at the wrong memory address, which may allow attackers to cause a denial of service (application crash) and possibly execute arbitrary code.

CAN-2005-1160

Remote attackers could override certain properties or methods of DOM nodes and gain privileges.

CAN-2005-1532

Remote attackers could override certain properties or methods due to missing proper limitation of Javascript eval and Script objects and gain privileges.

CAN-2005-2261

XML scripts ran even when Javascript disabled.

CAN-2005-2265

Missing input sanitising of InstallVersion.compareTo() can cause the application to crash.

CAN-2005-2266

Remote attackers could steal sensitive information such as cookies and passwords from web sites by accessing data in alien frames.

CAN-2005-2269

Remote attackers could modify certain tag properties of DOM nodes that could lead to the execution of arbitrary script or code.

CAN-2005-2270

The Mozilla browser family does not properly clone base objects, which allows remote attackers to execute arbitrary code.

The old stable distribution (woody) is not affected by these problems since it does not contain Mozilla Thunderbird packages.

For the stable distribution (sarge) these problems have been fixed in version 1.0.2-2.sarge1.0.6.

For the unstable distribution (sid) these problems have been fixed in version 1.0.6-1.

We recommend that you upgrade your Mozilla Thunderbird package.");

  script_tag(name:"affected", value:"'mozilla-thunderbird' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.0.2-2.sarge1.0.6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"1.0.2-2.sarge1.0.6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-inspector", ver:"1.0.2-2.sarge1.0.6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-offline", ver:"1.0.2-2.sarge1.0.6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-typeaheadfind", ver:"1.0.2-2.sarge1.0.6", rls:"DEB3.1"))) {
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

# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56777");
  script_cve_id("CVE-2006-2223", "CVE-2006-2224", "CVE-2006-2276");
  script_tag(name:"creation_date", value:"2008-01-17 22:09:45 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1059-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1059-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-1059-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1059");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'quagga' package(s) announced via the DSA-1059-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Konstantin Gavrilenko discovered several vulnerabilities in quagga, the BGP/OSPF/RIP routing daemon. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-2223

Remote attackers may obtain sensitive information via RIPv1 REQUEST packets even if the quagga has been configured to use MD5 authentication.

CVE-2006-2224

Remote attackers could inject arbitrary routes using the RIPv1 RESPONSE packet even if the quagga has been configured to use MD5 authentication.

CVE-2006-2276

Fredrik Widell discovered that local users can cause a denial of service in a certain sh ip bgp command entered in the telnet interface.

The old stable distribution (woody) does not contain quagga packages.

For the stable distribution (sarge) these problems have been fixed in version 0.98.3-7.2.

For the unstable distribution (sid) these problems have been fixed in version 0.99.4-1.

We recommend that you upgrade your quagga package.");

  script_tag(name:"affected", value:"'quagga' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"quagga", ver:"0.98.3-7.2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"quagga-doc", ver:"0.98.3-7.2", rls:"DEB3.1"))) {
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

# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53268");
  script_cve_id("CVE-1999-0710", "CVE-2004-0918");
  script_tag(name:"creation_date", value:"2008-01-17 21:45:44 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-576-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-576-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/DSA-576-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-576");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'squid' package(s) announced via the DSA-576-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in Squid, the internet object cache, the popular WWW proxy cache. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-1999-0710

It is possible to bypass access lists and scan arbitrary hosts and ports in the network through cachemgr.cgi, which is installed by default. This update disables this feature and introduces a configuration file (/etc/squid/cachemgr.conf) to control this behavior.

CAN-2004-0918

The asn_parse_header function (asn1.c) in the SNMP module for Squid allows remote attackers to cause a denial of service via certain SNMP packets with negative length fields that causes a memory allocation error.

For the stable distribution (woody) these problems have been fixed in version 2.4.6-2woody4.

For the unstable distribution (sid) these problems have been fixed in version 2.5.7-1.

We recommend that you upgrade your squid package.");

  script_tag(name:"affected", value:"'squid' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"squid", ver:"2.4.6-2woody4", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squid-cgi", ver:"2.4.6-2woody4", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squidclient", ver:"2.4.6-2woody4", rls:"DEB3.0"))) {
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

# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71824");
  script_cve_id("CVE-2012-1948", "CVE-2012-1950", "CVE-2012-1954", "CVE-2012-1967");
  script_tag(name:"creation_date", value:"2012-08-30 15:33:23 +0000 (Thu, 30 Aug 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2528-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2528-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2528-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2528");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icedove' package(s) announced via the DSA-2528-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Icedove, Debian's version of the Mozilla Thunderbird mail and news client.

CVE-2012-1948

Multiple unspecified vulnerabilities in the browser engine were fixed.

CVE-2012-1950

The underlying browser engine allows address bar spoofing through drag-and-drop.

CVE-2012-1954

A use-after-free vulnerability in the nsDocument::AdoptNode function allows remote attackers to cause a denial of service (heap memory corruption) or possibly execute arbitrary code.

CVE-2012-1967

An error in the implementation of the JavaScript sandbox allows execution of JavaScript code with improper privileges using javascript: URLs.

For the stable distribution (squeeze), these problems have been fixed in version 3.0.11-1+squeeze12.

For the testing distribution (wheezy) and the unstable distribution (sid), these problems have been fixed in version 10.0.6-1.

We recommend that you upgrade your icedove packages.");

  script_tag(name:"affected", value:"'icedove' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"icedove", ver:"3.0.11-1+squeeze12", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dbg", ver:"3.0.11-1+squeeze12", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dev", ver:"3.0.11-1+squeeze12", rls:"DEB6"))) {
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

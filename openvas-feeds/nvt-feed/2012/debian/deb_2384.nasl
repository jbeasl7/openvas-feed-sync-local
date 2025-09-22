# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70722");
  script_cve_id("CVE-2010-1644", "CVE-2010-1645", "CVE-2010-2543", "CVE-2010-2545", "CVE-2011-4824");
  script_tag(name:"creation_date", value:"2012-02-12 11:39:49 +0000 (Sun, 12 Feb 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2384-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2384-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2384-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2384");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cacti' package(s) announced via the DSA-2384-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Cacti, a graphing tool for monitoring data. Multiple cross site scripting issues allow remote attackers to inject arbitrary web script or HTML. An SQL injection vulnerability allows remote attackers to execute arbitrary SQL commands.

For the oldstable distribution (lenny), this problem has been fixed in version 0.8.7b-2.1+lenny5.

For the stable distribution (squeeze), this problem has been fixed in version 0.8.7g-1+squeeze1.

For the unstable distribution (sid), this problem has been fixed in version 0.8.7i-2.

We recommend that you upgrade your cacti packages.");

  script_tag(name:"affected", value:"'cacti' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"cacti", ver:"0.8.7b-2.1+lenny5", rls:"DEB5"))) {
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

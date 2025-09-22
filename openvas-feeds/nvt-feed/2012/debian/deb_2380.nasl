# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70699");
  script_cve_id("CVE-2011-2697", "CVE-2011-2964");
  script_tag(name:"creation_date", value:"2012-02-11 08:26:17 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2380-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");

  script_xref(name:"Advisory-ID", value:"DSA-2380-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2380-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2380");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'foomatic-filters' package(s) announced via the DSA-2380-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the foomatic-filters, a support package for setting up printers, allowed authenticated users to submit crafted print jobs which would execute shell commands on the print servers.

CVE-2011-2697 was assigned to the vulnerability in the Perl implementation included in lenny, and CVE-2011-2964 to the vulnerability affecting the C reimplementation part of squeeze.

For the oldstable distribution (lenny), this problem has been fixed in version 3.0.2-20080211-3.2+lenny1.

For the stable distribution (squeeze), this problem has been fixed in version 4.0.5-6+squeeze1.

For the testing distribution (wheezy) and the unstable distribution (sid), this problem has been fixed in version 4.0.9-1.

We recommend that you upgrade your foomatic-filters packages.");

  script_tag(name:"affected", value:"'foomatic-filters' package(s) on Debian 5, Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"foomatic-filters", ver:"3.0.2-20080211-3.2+lenny1", rls:"DEB5"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"foomatic-filters", ver:"4.0.5-6+squeeze1", rls:"DEB6"))) {
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

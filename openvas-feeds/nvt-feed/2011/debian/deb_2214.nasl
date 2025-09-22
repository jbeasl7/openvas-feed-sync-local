# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69558");
  script_cve_id("CVE-2011-1401");
  script_tag(name:"creation_date", value:"2011-05-12 17:21:50 +0000 (Thu, 12 May 2011)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2214-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");

  script_xref(name:"Advisory-ID", value:"DSA-2214-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2214-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2214");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ikiwiki' package(s) announced via the DSA-2214-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tango discovered that ikiwiki, a wiki compiler, is not validating if the htmlscrubber plugin is enabled or not on a page when adding alternative stylesheets to pages. This enables an attacker who is able to upload custom stylesheets to add malicious stylesheets as an alternate stylesheet, or replace the default stylesheet, and thus conduct cross-site scripting attacks.

For the oldstable distribution (lenny), this problem has been fixed in version 2.53.6.

For the stable distribution (squeeze), this problem has been fixed in version 3.20100815.7.

For the testing distribution (wheezy), this problem has been fixed in version 3.20110328.

For the unstable distribution (sid), this problem has been fixed in version 3.20110328.

We recommend that you upgrade your ikiwiki packages.");

  script_tag(name:"affected", value:"'ikiwiki' package(s) on Debian 5, Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ikiwiki", ver:"2.53.6", rls:"DEB5"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ikiwiki", ver:"3.20100815.7", rls:"DEB6"))) {
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

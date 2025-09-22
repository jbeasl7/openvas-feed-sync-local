# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69117");
  script_cve_id("CVE-2011-1018");
  script_tag(name:"creation_date", value:"2011-03-09 04:54:11 +0000 (Wed, 09 Mar 2011)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2182-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");

  script_xref(name:"Advisory-ID", value:"DSA-2182-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2182-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2182");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'logwatch' package(s) announced via the DSA-2182-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dominik George discovered that Logwatch does not guard against shell meta-characters in crafted log file names (such as those produced by Samba). As a result, an attacker might be able to execute shell commands on the system running Logwatch.

For the oldstable distribution (lenny), this problem has been fixed in version 7.3.6.cvs20080702-2lenny1.

For the stable distribution (squeeze), this problem has been fixed in version 7.3.6.cvs20090906-1squeeze1.

For the testing distribution (wheezy) and the unstable distribution (sid), this problem has been fixed in version 7.3.6.cvs20090906-2.

We recommend that you upgrade your logwatch packages.");

  script_tag(name:"affected", value:"'logwatch' package(s) on Debian 5, Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"logwatch", ver:"7.3.6.cvs20080702-2lenny1", rls:"DEB5"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"logwatch", ver:"7.3.6.cvs20090906-1squeeze1", rls:"DEB6"))) {
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

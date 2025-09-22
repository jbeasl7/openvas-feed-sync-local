# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60217");
  script_cve_id("CVE-2007-6350", "CVE-2007-6415");
  script_tag(name:"creation_date", value:"2008-01-31 15:11:48 +0000 (Thu, 31 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:N");

  script_name("Debian: Security Advisory (DSA-1473-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.1|4)");

  script_xref(name:"Advisory-ID", value:"DSA-1473-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1473-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1473");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'scponly' package(s) announced via the DSA-1473-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Joachim Breitner discovered that Subversion support in scponly is inherently insecure, allowing execution of arbitrary commands. Further investigation showed that rsync and Unison support suffer from similar issues. This set of issues has been assigned CVE-2007-6350.

In addition, it was discovered that it was possible to invoke scp with certain options that may lead to the execution of arbitrary commands (CVE-2007-6415).

This update removes Subversion, rsync and Unison support from the scponly package, and prevents scp from being invoked with the dangerous options.

For the old stable distribution (sarge), these problems have been fixed in version 4.0-1sarge2.

For the stable distribution (etch), these problems have been fixed in version 4.6-1etch1.

The unstable distribution (sid) will be fixed soon.

We recommend that you upgrade your scponly package.");

  script_tag(name:"affected", value:"'scponly' package(s) on Debian 3.1, Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"scponly", ver:"4.0-1sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"scponly", ver:"4.6-1etch1", rls:"DEB4"))) {
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

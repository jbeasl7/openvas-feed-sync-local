# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55973");
  script_cve_id("CVE-2005-3346", "CVE-2005-3533");
  script_tag(name:"creation_date", value:"2008-01-17 22:07:13 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-918-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.0|3\.1)");

  script_xref(name:"Advisory-ID", value:"DSA-918-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-918-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-918");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'osh' package(s) announced via the DSA-918-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security related problems have been discovered in osh, the operator's shell for executing defined programs in a privileged environment. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CVE-2005-3346

Charles Stevenson discovered a bug in the substitution of variables that allows a local attacker to open a root shell.

CVE-2005-3533

Solar Eclipse discovered a buffer overflow caused by the current working directory plus a filename that could be used to execute arbitrary code and e.g. open a root shell.

For the old stable distribution (woody) these problems have been fixed in version 1.7-11woody2.

For the stable distribution (sarge) these problems have been fixed in version 1.7-13sarge1.

For the unstable distribution (sid) these problems have been fixed in version 1.7-15, however, the package has been removed entirely.

We recommend that you upgrade your osh package.");

  script_tag(name:"affected", value:"'osh' package(s) on Debian 3.0, Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"osh", ver:"1.7-11woody2", rls:"DEB3.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"osh", ver:"1.7-13sarge1", rls:"DEB3.1"))) {
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

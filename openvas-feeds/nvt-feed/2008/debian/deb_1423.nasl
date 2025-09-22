# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.59958");
  script_cve_id("CVE-2007-5491", "CVE-2007-5492", "CVE-2007-5692", "CVE-2007-5693", "CVE-2007-5694", "CVE-2007-5695");
  script_tag(name:"creation_date", value:"2008-01-17 22:23:47 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1423-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.1|4)");

  script_xref(name:"Advisory-ID", value:"DSA-1423-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1423-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1423");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sitebar' package(s) announced via the DSA-1423-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in sitebar, a web based bookmark manager written in PHP. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-5491

A directory traversal vulnerability in the translation module allows remote authenticated users to chmod arbitrary files to 0777 via .. sequences in the lang parameter.

CVE-2007-5492

A static code injection vulnerability in the translation module allows a remote authenticated user to execute arbitrary PHP code via the value parameter.

CVE-2007-5693

An eval injection vulnerability in the translation module allows remote authenticated users to execute arbitrary PHP code via the edit parameter in an upd cmd action.

CVE-2007-5694

A path traversal vulnerability in the translation module allows remote authenticated users to read arbitrary files via an absolute path in the dir parameter.

CVE-2007-5695

An error in command.php allows remote attackers to redirect users to arbitrary web sites via the forward parameter in a Log In action.

CVE-2007-5692

Multiple cross site scripting flaws allow remote attackers to inject arbitrary script or HTML fragments into several scripts.

For the old stable distribution (sarge), these problems have been fixed in version 3.2.6-7.1sarge1.

For the stable distribution (etch), these problems have been fixed in version 3.3.8-7etch1.

For the unstable distribution (sid), these problems have been fixed in version 3.3.8-12.1.

We recommend that you upgrade your sitebar package.");

  script_tag(name:"affected", value:"'sitebar' package(s) on Debian 3.1, Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"sitebar", ver:"3.2.6-7.1sarge1", rls:"DEB3.1"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"sitebar", ver:"3.3.8-7etch1", rls:"DEB4"))) {
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

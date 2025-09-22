# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63792");
  script_cve_id("CVE-2008-3330", "CVE-2008-5917", "CVE-2009-0932");
  script_tag(name:"creation_date", value:"2009-04-15 20:11:00 +0000 (Wed, 15 Apr 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1765-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1765-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1765-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1765");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'horde3' package(s) announced via the DSA-1765-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in horde3, the horde web application framework. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0932

Gunnar Wrobel discovered a directory traversal vulnerability, which allows attackers to include and execute arbitrary local files via the driver parameter in Horde_Image.

CVE-2008-3330

It was discovered that an attacker could perform a cross-site scripting attack via the contact name, which allows attackers to inject arbitrary html code. This requires that the attacker has access to create contacts.

CVE-2008-5917

It was discovered that the horde XSS filter is prone to a cross-site scripting attack, which allows attackers to inject arbitrary html code. This is only exploitable when Internet Explorer is used.

For the oldstable distribution (etch), these problems have been fixed in version 3.1.3-4etch5.

For the stable distribution (lenny), these problems have been fixed in version 3.2.2+debian0-2, which was already included in the lenny release.

For the testing distribution (squeeze) and the unstable distribution (sid), these problems have been fixed in version 3.2.2+debian0-2.

We recommend that you upgrade your horde3 packages.");

  script_tag(name:"affected", value:"'horde3' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"horde3", ver:"3.1.3-4etch5", rls:"DEB4"))) {
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

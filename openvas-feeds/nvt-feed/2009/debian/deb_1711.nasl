# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63297");
  script_cve_id("CVE-2009-0255", "CVE-2009-0256", "CVE-2009-0257", "CVE-2009-0258");
  script_tag(name:"creation_date", value:"2009-02-02 22:28:24 +0000 (Mon, 02 Feb 2009)");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-14 16:10:04 +0000 (Wed, 14 Feb 2024)");

  script_name("Debian: Security Advisory (DSA-1711-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1711-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1711-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1711");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'typo3-src' package(s) announced via the DSA-1711-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remotely exploitable vulnerabilities have been discovered in the TYPO3 web content management framework. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0255

Chris John Riley discovered that the TYPO3-wide used encryption key is generated with an insufficiently random seed resulting in low entropy which makes it easier for attackers to crack this key.

CVE-2009-0256

Marcus Krause discovered that TYPO3 is not invalidating a supplied session on authentication which allows an attacker to take over a victims session via a session fixation attack.

CVE-2009-0257

Multiple cross-site scripting vulnerabilities allow remote attackers to inject arbitrary web script or HTML via various arguments and user supplied strings used in the indexed search system extension, adodb extension test scripts or the workspace module.

CVE-2009-0258

Mads Olesen discovered a remote command injection vulnerability in the indexed search system extension which allows attackers to execute arbitrary code via a crafted file name which is passed unescaped to various system tools that extract file content for the indexing.

Because of CVE-2009-0255, please make sure that besides installing this update, you also create a new encryption key after the installation.

For the stable distribution (etch) these problems have been fixed in version 4.0.2+debian-7.

For the unstable distribution (sid) these problems have been fixed in version 4.2.5-1.

We recommend that you upgrade your TYPO3 packages.");

  script_tag(name:"affected", value:"'typo3-src' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"typo3", ver:"4.0.2+debian-7", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"typo3-src-4.0", ver:"4.0.2+debian-7", rls:"DEB4"))) {
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

# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704036");
  script_cve_id("CVE-2017-8808", "CVE-2017-8809", "CVE-2017-8810", "CVE-2017-8811", "CVE-2017-8812", "CVE-2017-8814", "CVE-2017-8815");
  script_tag(name:"creation_date", value:"2017-11-14 23:00:00 +0000 (Tue, 14 Nov 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-28 16:56:08 +0000 (Tue, 28 Nov 2017)");

  script_name("Debian: Security Advisory (DSA-4036-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4036-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-4036-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4036");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mediawiki' package(s) announced via the DSA-4036-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities have been discovered in MediaWiki, a website engine for collaborative work:

CVE-2017-8808

Cross-site-scripting with non-standard URL escaping and $wgShowExceptionDetails disabled.

CVE-2017-8809

Reflected file download in API.

CVE-2017-8810

On private wikis the login form didn't distinguish between login failure due to bad username and bad password.

CVE-2017-8811

It was possible to mangle HTML via raw message parameter expansion.

CVE-2017-8812

id attributes in headlines allowed raw '>'.

CVE-2017-8814

Language converter could be tricked into replacing text inside tags.

CVE-2017-8815

Unsafe attribute injection via glossary rules in language converter.

For the stable distribution (stretch), these problems have been fixed in version 1:1.27.4-1~deb9u1.

We recommend that you upgrade your mediawiki packages.");

  script_tag(name:"affected", value:"'mediawiki' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"mediawiki", ver:"1:1.27.4-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mediawiki-classes", ver:"1:1.27.4-1~deb9u1", rls:"DEB9"))) {
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

# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70578");
  script_cve_id("CVE-2011-1578", "CVE-2011-1579", "CVE-2011-1580", "CVE-2011-1587", "CVE-2011-4360", "CVE-2011-4361");
  script_tag(name:"creation_date", value:"2012-02-11 07:34:53 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2366-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");

  script_xref(name:"Advisory-ID", value:"DSA-2366-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2366-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2366");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mediawiki' package(s) announced via the DSA-2366-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several problems have been discovered in MediaWiki, a website engine for collaborative work.

CVE-2011-1578 CVE-2011-1587 Masato Kinugawa discovered a cross-site scripting (XSS) issue, which affects Internet Explorer clients only, and only version 6 and earlier. Web server configuration changes are required to fix this issue. Upgrading MediaWiki will only be sufficient for people who use Apache with AllowOverride enabled. For details of the required configuration changes, see the upstream announcements.

CVE-2011-1579

Wikipedia user Suffusion of Yellow discovered a CSS validation error in the wikitext parser. This is an XSS issue for Internet Explorer clients, and a privacy loss issue for other clients since it allows the embedding of arbitrary remote images.

CVE-2011-1580

MediaWiki developer Happy-Melon discovered that the transwiki import feature neglected to perform access control checks on form submission. The transwiki import feature is disabled by default. If it is enabled, it allows wiki pages to be copied from a remote wiki listed in $wgImportSources. The issue means that any user can trigger such an import to occur.

CVE-2011-4360

Alexandre Emsenhuber discovered an issue where page titles on private wikis could be exposed bypassing different page ids to index.php. In the case of the user not having correct permissions, they will now be redirected to Special:BadTitle.

CVE-2011-4361

Tim Starling discovered that action=ajax requests were dispatched to the relevant function without any read permission checks being done. This could have led to data leakage on private wikis.

For the oldstable distribution (lenny), these problems have been fixed in version 1:1.12.0-2lenny9.

For the stable distribution (squeeze), these problems have been fixed in version 1:1.15.5-2squeeze2.

For the unstable distribution (sid), these problems have been fixed in version 1:1.15.5-5.

We recommend that you upgrade your mediawiki packages.");

  script_tag(name:"affected", value:"'mediawiki' package(s) on Debian 5, Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mediawiki", ver:"1:1.12.0-2lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mediawiki-math", ver:"1:1.12.0-2lenny9", rls:"DEB5"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"mediawiki", ver:"1:1.15.5-2squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mediawiki-math", ver:"1:1.15.5-2squeeze2", rls:"DEB6"))) {
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

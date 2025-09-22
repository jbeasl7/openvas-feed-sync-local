# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58326");
  script_cve_id("CVE-2007-0002", "CVE-2007-0238", "CVE-2007-0239");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1270-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1270-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1270-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1270");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openoffice.org' package(s) announced via the DSA-1270-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security related problems have been discovered in OpenOffice.org, the free office suite. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-0002

iDefense reported several integer overflow bugs in libwpd, a library for handling WordPerfect documents that is included in OpenOffice.org. Attackers are able to exploit these with carefully crafted WordPerfect files that could cause an application linked with libwpd to crash or possibly execute arbitrary code.

CVE-2007-0238

Next Generation Security discovered that the StarCalc parser in OpenOffice.org contains an easily exploitable stack overflow that could be used by a specially crafted document to execute arbitrary code.

CVE-2007-0239

It has been reported that OpenOffice.org does not escape shell meta characters and is hence vulnerable to execute arbitrary shell commands via a specially crafted document after the user clicked to a prepared link.

This updated advisory only provides packages for the upcoming etch release alias Debian GNU/Linux 4.0.

For the stable distribution (sarge) these problems have been fixed in version 1.1.3-9sarge6.

For the testing distribution (etch) these problems have been fixed in version 2.0.4.dfsg.2-5etch1.

For the unstable distribution (sid) these problems have been fixed in version 2.0.4.dfsg.2-6.

We recommend that you upgrade your OpenOffice.org packages.");

  script_tag(name:"affected", value:"'openoffice.org' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-bin", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-dev", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-evolution", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-gtk-gnome", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-kde", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-af", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ar", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ca", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-cs", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-cy", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-da", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-de", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-el", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-en", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-es", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-et", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-eu", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-fi", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-fr", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-gl", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-he", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-hi", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-hu", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-it", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ja", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-kn", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ko", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-lt", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-nb", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-nl", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-nn", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ns", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-pl", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-pt", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-pt-br", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ru", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sk", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sl", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sv", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-th", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-tn", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-tr", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-cn", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-tw", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-zu", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-mimelnk", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-thesaurus-en-us", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ttf-opensymbol", ver:"1.1.3-9sarge6", rls:"DEB3.1"))) {
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

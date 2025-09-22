# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702718");
  script_cve_id("CVE-2013-2173", "CVE-2013-2199", "CVE-2013-2200", "CVE-2013-2201", "CVE-2013-2202", "CVE-2013-2203", "CVE-2013-2204", "CVE-2013-2205");
  script_tag(name:"creation_date", value:"2013-06-30 22:00:00 +0000 (Sun, 30 Jun 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2718-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2718-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/DSA-2718-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2718");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wordpress' package(s) announced via the DSA-2718-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were identified in WordPress, a web blogging tool. As the CVEs were allocated from releases announcements and specific fixes are usually not identified, it has been decided to upgrade the wordpress package to the latest upstream version instead of backporting the patches.

This means extra care should be taken when upgrading, especially when using third-party plugins or themes, since compatibility may have been impacted along the way. We recommend that users check their install before doing the upgrade.

CVE-2013-2173

A denial of service was found in the way WordPress performs hash computation when checking password for protected posts. An attacker supplying carefully crafted input as a password could make the platform use excessive CPU usage.

CVE-2013-2199

Multiple server-side requests forgery (SSRF) vulnerabilities were found in the HTTP API. This is related to CVE-2013-0235, which was specific to SSRF in pingback requests and was fixed in 3.5.1.

CVE-2013-2200

Inadequate checking of a user's capabilities could lead to a privilege escalation, enabling them to publish posts when their user role should not allow for it and to assign posts to other authors.

CVE-2013-2201

Multiple cross-side scripting (XSS) vulnerabilities due to badly escaped input were found in the media files and plugins upload forms.

CVE-2013-2202

XML External Entity Injection (XXE) vulnerability via oEmbed responses.

CVE-2013-2203

A Full path disclosure (FPD) was found in the file upload mechanism. If the upload directory is not writable, the error message returned includes the full directory path.

CVE-2013-2204

Content spoofing via Flash applet in the embedded tinyMCE media plugin.

CVE-2013-2205

Cross-domain XSS in the embedded SWFupload uploader.

For the oldstable distribution (squeeze), these problems have been fixed in version 3.5.2+dfsg-1~deb6u1.

For the stable distribution (wheezy), these problems have been fixed in version 3.5.2+dfsg-1~deb7u1.

For the testing distribution (jessie), these problems have been fixed in version 3.5.2+dfsg-1.

For the unstable distribution (sid), these problems have been fixed in version 3.5.2+dfsg-1.

We recommend that you upgrade your wordpress packages.");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian 6, Debian 7.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"3.5.2+dfsg-1~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-l10n", ver:"3.5.2+dfsg-1~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"3.5.2+dfsg-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-l10n", ver:"3.5.2+dfsg-1~deb7u1", rls:"DEB7"))) {
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

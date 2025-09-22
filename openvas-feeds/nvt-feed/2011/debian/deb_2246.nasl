# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69743");
  script_cve_id("CVE-2011-1402", "CVE-2011-1403", "CVE-2011-1404", "CVE-2011-1405", "CVE-2011-1406");
  script_tag(name:"creation_date", value:"2011-08-03 02:36:20 +0000 (Wed, 03 Aug 2011)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2246-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");

  script_xref(name:"Advisory-ID", value:"DSA-2246-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2246-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2246");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mahara' package(s) announced via the DSA-2246-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Mahara, an electronic portfolio, weblog, and resume builder. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2011-1402

It was discovered that previous versions of Mahara did not check user credentials before adding a secret URL to a view or suspending a user.

CVE-2011-1403

Due to a misconfiguration of the Pieform package in Mahara, the cross-site request forgery protection mechanism that Mahara relies on to harden its form was not working and was essentially disabled. This is a critical vulnerability which could allow attackers to trick other users (for example administrators) into performing malicious actions on behalf of the attacker. Most Mahara forms are vulnerable.

CVE-2011-1404

Many of the JSON structures returned by Mahara for its AJAX interactions included more information than what ought to be disclosed to the logged in user. New versions of Mahara limit this information to what is necessary for each page.

CVE-2011-1405

Previous versions of Mahara did not escape the contents of HTML emails sent to users. Depending on the filters enabled in one's mail reader, it could lead to cross-site scripting attacks.

CVE-2011-1406

It has been pointed out to us that if Mahara is configured (through its wwwroot variable) to use HTTPS, it will happily let users login via the HTTP version of the site if the web server is configured to serve content over both protocol. The new version of Mahara will, when the wwwroot points to an HTTPS URL, automatically redirect to HTTPS if it detects that it is being run over HTTP.

We recommend that sites wanting to run Mahara over HTTPS make sure that their web server configuration does not allow the serving of content over HTTP and merely redirects to the secure version. We also suggest that site administrators consider adding the HSTS headers to their web server configuration.

For the oldstable distribution (lenny), these problems have been fixed in version 1.0.4-4+lenny10.

For the stable distribution (squeeze), these problems have been fixed in version 1.2.6-2+squeeze2.

For the testing distribution (wheezy), these problems have been fixed in version 1.3.6-1.

For the unstable distribution (sid), these problems have been fixed in version 1.3.6-1.

We recommend that you upgrade your mahara packages.");

  script_tag(name:"affected", value:"'mahara' package(s) on Debian 5, Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mahara", ver:"1.0.4-4+lenny10", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mahara-apache2", ver:"1.0.4-4+lenny10", rls:"DEB5"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"mahara", ver:"1.2.6-2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mahara-apache2", ver:"1.2.6-2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mahara-mediaplayer", ver:"1.2.6-2+squeeze2", rls:"DEB6"))) {
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

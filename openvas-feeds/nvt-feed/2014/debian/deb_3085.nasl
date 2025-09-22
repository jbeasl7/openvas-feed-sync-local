# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703085");
  script_cve_id("CVE-2014-9031", "CVE-2014-9033", "CVE-2014-9034", "CVE-2014-9035", "CVE-2014-9036", "CVE-2014-9037", "CVE-2014-9038", "CVE-2014-9039");
  script_tag(name:"creation_date", value:"2014-12-02 23:00:00 +0000 (Tue, 02 Dec 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3085-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3085-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-3085-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3085");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wordpress' package(s) announced via the DSA-3085-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been discovered in Wordpress, a web blogging tool, resulting in denial of service or information disclosure. More information can be found in the upstream advisory at

CVE-2014-9031

Jouko Pynnonen discovered an unauthenticated cross site scripting vulnerability (XSS) in wptexturize(), exploitable via comments or posts.

CVE-2014-9033

Cross site request forgery (CSRF) vulnerability in the password changing process, which could be used by an attacker to trick an user into changing her password.

CVE-2014-9034

Javier Nieto Arevalo and Andres Rojas Guerrero reported a potential denial of service in the way the phpass library is used to handle passwords, since no maximum password length was set.

CVE-2014-9035

John Blackbourn reported an XSS in the Press This function (used for quick publishing using a browser bookmarklet).

CVE-2014-9036

Robert Chapin reported an XSS in the HTML filtering of CSS in posts.

CVE-2014-9037

David Anderson reported a hash comparison vulnerability for passwords stored using the old-style MD5 scheme. While unlikely, this could be exploited to compromise an account, if the user had not logged in after a Wordpress 2.5 update (uploaded to Debian on 2 Apr, 2008) and the password MD5 hash could be collided with due to PHP dynamic comparison.

CVE-2014-9038

Ben Bidner reported a server side request forgery (SSRF) in the core HTTP layer which unsufficiently blocked the loopback IP address space.

CVE-2014-9039

Momen Bassel, Tanoy Bose, and Bojan Slavkovic reported a vulnerability in the password reset process: an email address change would not invalidate a previous password reset email.

For the stable distribution (wheezy), these problems have been fixed in version 3.6.1+dfsg-1~deb7u5.

For the upcoming stable distribution (jessie), these problems have been fixed in version 4.0.1+dfsg-1.

For the unstable distribution (sid), these problems have been fixed in version 4.0.1+dfsg-1.

We recommend that you upgrade your wordpress packages.");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"3.6.1+dfsg-1~deb7u5", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-l10n", ver:"3.6.1+dfsg-1~deb7u5", rls:"DEB7"))) {
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

# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71149");
  script_cve_id("CVE-2011-4308", "CVE-2011-4584", "CVE-2011-4585", "CVE-2011-4586", "CVE-2011-4587", "CVE-2011-4588", "CVE-2012-0792", "CVE-2012-0793", "CVE-2012-0794", "CVE-2012-0795", "CVE-2012-0796");
  script_tag(name:"creation_date", value:"2012-03-12 15:32:57 +0000 (Mon, 12 Mar 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2421-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2421-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2421-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2421");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'moodle' package(s) announced via the DSA-2421-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues have been fixed in Moodle, a course management system for online learning:

CVE-2011-4308 / CVE-2012-0792 Rossiani Wijaya discovered an information leak in mod/forum/user.php.

CVE-2011-4584

MNet authentication didn't prevent a user using Login as from jumping to a remove MNet SSO.

CVE-2011-4585

Darragh Enright discovered that the change password form was send in over plain HTTP even if httpslogin was set to true.

CVE-2011-4586

David Michael Evans and German Sanchez Gances discovered CRLF injection/HTTP response splitting vulnerabilities in the Calendar module.

CVE-2011-4587

Stephen Mc Guiness discovered empty passwords could be entered in some circumstances.

CVE-2011-4588

Patrick McNeill discovered that IP address restrictions could be bypassed in MNet.

CVE-2012-0796

Simon Coggins discovered that additional information could be injected into mail headers.

CVE-2012-0795

John Ehringer discovered that email addresses were insufficiently validated.

CVE-2012-0794

Rajesh Taneja discovered that cookie encryption used a fixed key.

CVE-2012-0793

Eloy Lafuente discovered that profile images were insufficiently protected. A new configuration option forceloginforprofileimages was introduced for that.

For the stable distribution (squeeze), this problem has been fixed in version 1.9.9.dfsg2-2.1+squeeze3.

For the unstable distribution (sid), this problem has been fixed in version 1.9.9.dfsg2-5.

We recommend that you upgrade your moodle packages.");

  script_tag(name:"affected", value:"'moodle' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"moodle", ver:"1.9.9.dfsg2-2.1+squeeze3", rls:"DEB6"))) {
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

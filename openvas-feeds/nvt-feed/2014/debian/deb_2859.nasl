# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702859");
  script_cve_id("CVE-2013-6477", "CVE-2013-6478", "CVE-2013-6479", "CVE-2013-6481", "CVE-2013-6482", "CVE-2013-6483", "CVE-2013-6484", "CVE-2013-6485", "CVE-2013-6487", "CVE-2013-6489", "CVE-2013-6490", "CVE-2014-0020");
  script_tag(name:"creation_date", value:"2014-02-09 23:00:00 +0000 (Sun, 09 Feb 2014)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2859-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2859-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2859-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2859");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pidgin' package(s) announced via the DSA-2859-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Pidgin, a multi-protocol instant messaging client:

CVE-2013-6477

Jaime Breva Ribes discovered that a remote XMPP user can trigger a crash by sending a message with a timestamp in the distant future.

CVE-2013-6478

Pidgin could be crashed through overly wide tooltip windows.

CVE-2013-6479

Jacob Appelbaum discovered that a malicious server or a man in the middle could send a malformed HTTP header resulting in denial of service.

CVE-2013-6481

Daniel Atallah discovered that Pidgin could be crashed through malformed Yahoo! P2P messages.

CVE-2013-6482

Fabian Yamaguchi and Christian Wressnegger discovered that Pidgin could be crashed through malformed MSN messages.

CVE-2013-6483

Fabian Yamaguchi and Christian Wressnegger discovered that Pidgin could be crashed through malformed XMPP messages.

CVE-2013-6484

It was discovered that incorrect error handling when reading the response from a STUN server could result in a crash.

CVE-2013-6485

Matt Jones discovered a buffer overflow in the parsing of malformed HTTP responses.

CVE-2013-6487

Yves Younan and Ryan Pentney discovered a buffer overflow when parsing Gadu-Gadu messages.

CVE-2013-6489

Yves Younan and Pawel Janic discovered an integer overflow when parsing MXit emoticons.

CVE-2013-6490

Yves Younan discovered a buffer overflow when parsing SIMPLE headers.

CVE-2014-0020

Daniel Atallah discovered that Pidgin could be crashed via malformed IRC arguments.

For the oldstable distribution (squeeze), no direct backport is provided. A fixed package will be provided through backports.debian.org shortly.

For the stable distribution (wheezy), these problems have been fixed in version 2.10.9-1~deb7u1.

For the unstable distribution (sid), these problems have been fixed in version 2.10.9-1.

We recommend that you upgrade your pidgin packages.");

  script_tag(name:"affected", value:"'pidgin' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"finch", ver:"2.7.3-1+squeeze4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"finch-dev", ver:"2.7.3-1+squeeze4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpurple-bin", ver:"2.7.3-1+squeeze4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpurple-dev", ver:"2.7.3-1+squeeze4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpurple0", ver:"2.7.3-1+squeeze4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pidgin", ver:"2.7.3-1+squeeze4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pidgin-data", ver:"2.7.3-1+squeeze4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pidgin-dbg", ver:"2.7.3-1+squeeze4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pidgin-dev", ver:"2.7.3-1+squeeze4", rls:"DEB6"))) {
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

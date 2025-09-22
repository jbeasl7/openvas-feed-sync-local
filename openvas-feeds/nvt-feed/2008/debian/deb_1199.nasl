# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57540");
  script_cve_id("CVE-2005-3912", "CVE-2006-3392", "CVE-2006-4542");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1199-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1199-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-1199-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1199");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'webmin' package(s) announced via the DSA-1199-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been identified in webmin, a web-based administration toolkit. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CVE-2005-3912

A format string vulnerability in miniserv.pl could allow an attacker to cause a denial of service by crashing the application or exhausting system resources, and could potentially allow arbitrary code execution.

CVE-2006-3392

Improper input sanitization in miniserv.pl could allow an attacker to read arbitrary files on the webmin host by providing a specially crafted URL path to the miniserv http server.

CVE-2006-4542

Improper handling of null characters in URLs in miniserv.pl could allow an attacker to conduct cross-site scripting attacks, read CGI program source code, list local directories, and potentially execute arbitrary code.

Stable updates are available for alpha, amd64, arm, hppa, i386, ia64, m68k, mips, mipsel, powerpc, s390 and sparc.

For the stable distribution (sarge), these problems have been fixed in version 1.180-3sarge1.

Webmin is not included in unstable (sid) or testing (etch), so these problems are not present.

We recommend that you upgrade your webmin (1.180-3sarge1) package.");

  script_tag(name:"affected", value:"'webmin' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"webmin", ver:"1.180-3sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"webmin-core", ver:"1.180-3sarge1", rls:"DEB3.1"))) {
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

# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702584");
  script_cve_id("CVE-2012-4201", "CVE-2012-4207", "CVE-2012-4216", "CVE-2012-5829", "CVE-2012-5842");
  script_tag(name:"creation_date", value:"2013-09-18 09:53:02 +0000 (Wed, 18 Sep 2013)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2584-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2584-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2584-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2584");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceape' package(s) announced via the DSA-2584-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in Iceape, the Debian Internet suite based on Mozilla Seamonkey:

CVE-2012-5829

Heap-based buffer overflow in the nsWindow::OnExposeEvent function could allow remote attackers to execute arbitrary code.

CVE-2012-5842

Multiple unspecified vulnerabilities in the browser engine could allow remote attackers to cause a denial of service (memory corruption and application crash) or possibly execute arbitrary code.

CVE-2012-4207

The HZ-GB-2312 character-set implementation does not properly handle a ~ (tilde) character in proximity to a chunk delimiter, which allows remote attackers to conduct cross-site scripting (XSS) attacks via a crafted document.

CVE-2012-4201

The evalInSandbox implementation uses an incorrect context during the handling of JavaScript code that sets the location.href property, which allows remote attackers to conduct cross-site scripting (XSS) attacks or read arbitrary files by leveraging a sandboxed add-on.

CVE-2012-4216

Use-after-free vulnerability in the gfxFont::GetFontEntry function allows remote attackers to execute arbitrary code or cause a denial of service (heap memory corruption) via unspecified vectors.

For the stable distribution (squeeze), these problems have been fixed in version 2.0.11-17.

For the testing distribution (wheezy), these problems have been fixed in version 2.7.11-1.

For the unstable distribution (sid), these problems have been fixed in version 2.7.11-1.

We recommend that you upgrade your iceape packages.");

  script_tag(name:"affected", value:"'iceape' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"iceape", ver:"2.0.11-17", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-browser", ver:"2.0.11-17", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-chatzilla", ver:"2.0.11-17", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-dbg", ver:"2.0.11-17", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-dev", ver:"2.0.11-17", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-mailnews", ver:"2.0.11-17", rls:"DEB6"))) {
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

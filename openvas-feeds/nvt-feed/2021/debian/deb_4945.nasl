# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704945");
  script_cve_id("CVE-2021-21775", "CVE-2021-21779", "CVE-2021-30663", "CVE-2021-30665", "CVE-2021-30689", "CVE-2021-30720", "CVE-2021-30734", "CVE-2021-30744", "CVE-2021-30749", "CVE-2021-30758", "CVE-2021-30795", "CVE-2021-30797", "CVE-2021-30799");
  script_tag(name:"creation_date", value:"2021-07-30 03:00:16 +0000 (Fri, 30 Jul 2021)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-15 19:45:31 +0000 (Wed, 15 Sep 2021)");

  script_name("Debian: Security Advisory (DSA-4945-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4945-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/DSA-4945-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4945");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/webkit2gtk");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'webkit2gtk' package(s) announced via the DSA-4945-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities have been discovered in the webkit2gtk web engine:

CVE-2021-21775

Marcin Towalski discovered that a specially crafted web page can lead to a potential information leak and further memory corruption. In order to trigger the vulnerability, a victim must be tricked into visiting a malicious webpage.

CVE-2021-21779

Marcin Towalski discovered that a specially crafted web page can lead to a potential information leak and further memory corruption. In order to trigger the vulnerability, a victim must be tricked into visiting a malicious webpage.

CVE-2021-30663

An anonymous researcher discovered that processing maliciously crafted web content may lead to arbitrary code execution.

CVE-2021-30665

yangkang discovered that processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited.

CVE-2021-30689

An anonymous researcher discovered that processing maliciously crafted web content may lead to universal cross site scripting.

CVE-2021-30720

David Schutz discovered that a malicious website may be able to access restricted ports on arbitrary servers.

CVE-2021-30734

Jack Dates discovered that processing maliciously crafted web content may lead to arbitrary code execution.

CVE-2021-30744

Dan Hite discovered that processing maliciously crafted web content may lead to universal cross site scripting.

CVE-2021-30749

An anonymous researcher discovered that processing maliciously crafted web content may lead to arbitrary code execution.

CVE-2021-30758

Christoph Guttandin discovered that processing maliciously crafted web content may lead to arbitrary code execution.

CVE-2021-30795

Sergei Glazunov discovered that processing maliciously crafted web content may lead to arbitrary code execution.

CVE-2021-30797

Ivan Fratric discovered that processing maliciously crafted web content may lead to code execution.

CVE-2021-30799

Sergei Glazunov discovered that processing maliciously crafted web content may lead to arbitrary code execution.

For the stable distribution (buster), these problems have been fixed in version 2.32.3-1~deb10u1.

We recommend that you upgrade your webkit2gtk packages.

For the detailed security status of webkit2gtk please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'webkit2gtk' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-javascriptcoregtk-4.0", ver:"2.32.3-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-webkit2-4.0", ver:"2.32.3-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.0-18", ver:"2.32.3-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.0-bin", ver:"2.32.3-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.0-dev", ver:"2.32.3-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-37", ver:"2.32.3-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-37-gtk2", ver:"2.32.3-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-dev", ver:"2.32.3-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-doc", ver:"2.32.3-1~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"webkit2gtk-driver", ver:"2.32.3-1~deb10u1", rls:"DEB10"))) {
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

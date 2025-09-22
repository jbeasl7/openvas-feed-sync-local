# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893289");
  script_cve_id("CVE-2020-4051", "CVE-2021-23450");
  script_tag(name:"creation_date", value:"2023-01-30 09:59:02 +0000 (Mon, 30 Jan 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-27 18:13:48 +0000 (Mon, 27 Dec 2021)");

  script_name("Debian: Security Advisory (DLA-3289-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3289-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3289-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/dojo");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dojo' package(s) announced via the DLA-3289-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were found in dojo, a modular JavaScript toolkit, that could result in information disclosure.

CVE-2020-4051

The Dijit Editor's LinkDialog plugin of dojo 1.14.0 to 1.14.7 is vulnerable to cross-site scripting (XSS) attacks.

CVE-2021-23450

Prototype pollution vulnerability via the setObject() function.

For Debian 10 buster, these problems have been fixed in version 1.14.2+dfsg1-1+deb10u3.

We recommend that you upgrade your dojo packages.

For the detailed security status of dojo please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'dojo' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"libjs-dojo-core", ver:"1.14.2+dfsg1-1+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjs-dojo-dijit", ver:"1.14.2+dfsg1-1+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjs-dojo-dojox", ver:"1.14.2+dfsg1-1+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"shrinksafe", ver:"1.14.2+dfsg1-1+deb10u3", rls:"DEB10"))) {
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

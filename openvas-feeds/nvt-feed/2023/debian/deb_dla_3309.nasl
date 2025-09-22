# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893309");
  script_cve_id("CVE-2022-4728", "CVE-2022-4729", "CVE-2022-4730");
  script_tag(name:"creation_date", value:"2023-02-08 02:00:14 +0000 (Wed, 08 Feb 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-05 18:48:53 +0000 (Thu, 05 Jan 2023)");

  script_name("Debian: Security Advisory (DLA-3309-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3309-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3309-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'graphite-web' package(s) announced via the DLA-3309-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there were a number of issues in graphite-web, a tool provide realtime graphing of system statistics etc.

A series of cross-site scripting (XSS) vulnerabilities existed that could have been exploited remotely. Issues existed in the Cookie Handler, Template Name Handler and Absolute Time Range Handler components:

CVE-2022-4728

A vulnerability has been found in Graphite Web and classified as problematic. This vulnerability affects unknown code of the component Cookie Handler. The manipulation leads to cross site scripting. VDB-216742 is the identifier assigned to this vulnerability.

CVE-2022-4729

A vulnerability was found in Graphite Web and classified as problematic. This issue affects some unknown processing of the component Template Name Handler. The manipulation leads to cross site scripting. The associated identifier of this vulnerability is VDB-216743.

CVE-2022-4730

A vulnerability was found in Graphite Web. It has been classified as problematic. Affected is an unknown function of the component Absolute Time Range Handler. The manipulation leads to cross site scripting. The identifier of this vulnerability is VDB-216744.

For Debian 10 Buster, these problems have been fixed in version 1.1.4-3+deb10u2.

We recommend that you upgrade your graphite-web packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'graphite-web' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"graphite-web", ver:"1.1.4-3+deb10u2", rls:"DEB10"))) {
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

# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893031");
  script_cve_id("CVE-2021-42717");
  script_tag(name:"creation_date", value:"2022-06-01 13:28:05 +0000 (Wed, 01 Jun 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-10 01:36:23 +0000 (Fri, 10 Dec 2021)");

  script_name("Debian: Security Advisory (DLA-3031-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-3031-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-3031-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'modsecurity-apache' package(s) announced via the DLA-3031-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a potential resource exhaustion attack in modsecurity-apache, an Apache module which inspects HTTP requests with the aim of preventing typical web application attacks such as XSS and SQL.

CVE-2021-42717

ModSecurity 3.x through 3.0.5 mishandles excessively nested JSON objects. Crafted JSON objects with nesting tens-of-thousands deep could result in the web server being unable to service legitimate requests. Even a moderately large (e.g., 300KB) HTTP request can occupy one of the limited NGINX worker processes for minutes and consume almost all of the available CPU on the machine. Modsecurity 2 is similarly vulnerable: the affected versions include 2.8.0 through 2.9.4.

For Debian 9 Stretch, this problem has been fixed in version 2.9.1-2+deb9u1.

We recommend that you upgrade your modsecurity-apache packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'modsecurity-apache' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-security2", ver:"2.9.1-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-modsecurity", ver:"2.9.1-2+deb9u1", rls:"DEB9"))) {
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

# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892980");
  script_cve_id("CVE-2022-24349", "CVE-2022-24917", "CVE-2022-24919");
  script_tag(name:"creation_date", value:"2022-04-13 01:00:08 +0000 (Wed, 13 Apr 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-17 13:28:28 +0000 (Thu, 17 Mar 2022)");

  script_name("Debian: Security Advisory (DLA-2980-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2980-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-2980-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/zabbix");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'zabbix' package(s) announced via the DLA-2980-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in zabbix, a network monitoring solution. An authenticated user can create a link with reflected Javascript code inside it for graphs, actions and services pages and send it to other users. The payload can be executed only with a known CSRF token value of the victim, which is changed periodically and is difficult to predict.

For Debian 9 stretch, these problems have been fixed in version 1:3.0.32+dfsg-0+deb9u3.

We recommend that you upgrade your zabbix packages.

For the detailed security status of zabbix please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'zabbix' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-agent", ver:"1:3.0.32+dfsg-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-frontend-php", ver:"1:3.0.32+dfsg-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-java-gateway", ver:"1:3.0.32+dfsg-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-mysql", ver:"1:3.0.32+dfsg-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-pgsql", ver:"1:3.0.32+dfsg-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-sqlite3", ver:"1:3.0.32+dfsg-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-server-mysql", ver:"1:3.0.32+dfsg-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-server-pgsql", ver:"1:3.0.32+dfsg-0+deb9u3", rls:"DEB9"))) {
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

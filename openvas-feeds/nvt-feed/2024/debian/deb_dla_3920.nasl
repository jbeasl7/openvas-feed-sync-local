# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2024.3920");
  script_cve_id("CVE-2022-4900", "CVE-2024-5458", "CVE-2024-8925", "CVE-2024-8927", "CVE-2024-9026");
  script_tag(name:"creation_date", value:"2024-10-15 04:20:50 +0000 (Tue, 15 Oct 2024)");
  script_version("2024-10-17T08:02:35+0000");
  script_tag(name:"last_modification", value:"2024-10-17 08:02:35 +0000 (Thu, 17 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-16 18:28:34 +0000 (Wed, 16 Oct 2024)");

  script_name("Debian: Security Advisory (DLA-3920-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DLA-3920-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2024/DLA-3920-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php7.4' package(s) announced via the DLA-3920-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'php7.4' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php7.4", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libphp7.4-embed", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-bcmath", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-bz2", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-cgi", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-cli", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-common", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-curl", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-dba", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-dev", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-enchant", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-fpm", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-gd", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-gmp", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-imap", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-interbase", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-intl", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-json", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-ldap", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-mbstring", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-mysql", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-odbc", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-opcache", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-pgsql", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-phpdbg", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-pspell", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-readline", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-snmp", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-soap", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-sqlite3", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-sybase", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-tidy", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-xml", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-xmlrpc", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-xsl", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-zip", ver:"7.4.33-1+deb11u6", rls:"DEB11"))) {
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

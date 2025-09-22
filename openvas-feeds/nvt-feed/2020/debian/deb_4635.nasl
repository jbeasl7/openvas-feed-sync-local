# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704635");
  script_cve_id("CVE-2020-9273");
  script_tag(name:"creation_date", value:"2020-02-27 04:00:07 +0000 (Thu, 27 Feb 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-21 18:44:00 +0000 (Fri, 21 Feb 2020)");

  script_name("Debian: Security Advisory (DSA-4635-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4635-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4635-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4635");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/proftpd-dfsg");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'proftpd-dfsg' package(s) announced via the DSA-4635-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Antonio Morales discovered an use-after-free flaw in the memory pool allocator in ProFTPD, a powerful modular FTP/SFTP/FTPS server. Interrupting current data transfers can corrupt the ProFTPD memory pool, leading to denial of service, or potentially the execution of arbitrary code.

For the oldstable distribution (stretch), this problem has been fixed in version 1.3.5b-4+deb9u4.

For the stable distribution (buster), this problem has been fixed in version 1.3.6-4+deb10u4.

We recommend that you upgrade your proftpd-dfsg packages.

For the detailed security status of proftpd-dfsg please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'proftpd-dfsg' package(s) on Debian 9, Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-basic", ver:"1.3.6-4+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-dev", ver:"1.3.6-4+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-doc", ver:"1.3.6-4+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-mod-geoip", ver:"1.3.6-4+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-mod-ldap", ver:"1.3.6-4+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-mod-mysql", ver:"1.3.6-4+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-mod-odbc", ver:"1.3.6-4+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-mod-pgsql", ver:"1.3.6-4+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-mod-snmp", ver:"1.3.6-4+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-mod-sqlite", ver:"1.3.6-4+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-basic", ver:"1.3.5b-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-dev", ver:"1.3.5b-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-doc", ver:"1.3.5b-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-mod-geoip", ver:"1.3.5b-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-mod-ldap", ver:"1.3.5b-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-mod-mysql", ver:"1.3.5b-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-mod-odbc", ver:"1.3.5b-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-mod-pgsql", ver:"1.3.5b-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-mod-sqlite", ver:"1.3.5b-4+deb9u4", rls:"DEB9"))) {
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

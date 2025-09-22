# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891607");
  script_cve_id("CVE-2018-14629", "CVE-2018-16851");
  script_tag(name:"creation_date", value:"2018-12-17 23:00:00 +0000 (Mon, 17 Dec 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-04 20:11:17 +0000 (Mon, 04 Feb 2019)");

  script_name("Debian: Security Advisory (DLA-1607-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1607-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1607-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'samba' package(s) announced via the DLA-1607-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Samba, a SMB/CIFS file, print, and login server for Unix. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2018-14629

Florian Stuelpner discovered that Samba is vulnerable to infinite query recursion caused by CNAME loops, resulting in denial of service.

CVE-2018-16851

Garming Sam of the Samba Team and Catalyst discovered a NULL pointer dereference vulnerability in the Samba AD DC LDAP server allowing a user able to read more than 256MB of LDAP entries to crash the Samba AD DC's LDAP server.

For Debian 8 Jessie, these problems have been fixed in version 2:4.2.14+dfsg-0+deb8u11.

We recommend that you upgrade your samba packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'samba' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"ctdb", ver:"2:4.2.14+dfsg-0+deb8u11", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss-winbind", ver:"2:4.2.14+dfsg-0+deb8u11", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpam-smbpass", ver:"2:4.2.14+dfsg-0+deb8u11", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpam-winbind", ver:"2:4.2.14+dfsg-0+deb8u11", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libparse-pidl-perl", ver:"2:4.2.14+dfsg-0+deb8u11", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsmbclient", ver:"2:4.2.14+dfsg-0+deb8u11", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"2:4.2.14+dfsg-0+deb8u11", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwbclient-dev", ver:"2:4.2.14+dfsg-0+deb8u11", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwbclient0", ver:"2:4.2.14+dfsg-0+deb8u11", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-samba", ver:"2:4.2.14+dfsg-0+deb8u11", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"registry-tools", ver:"2:4.2.14+dfsg-0+deb8u11", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:4.2.14+dfsg-0+deb8u11", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-common", ver:"2:4.2.14+dfsg-0+deb8u11", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-common-bin", ver:"2:4.2.14+dfsg-0+deb8u11", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-dbg", ver:"2:4.2.14+dfsg-0+deb8u11", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-dev", ver:"2:4.2.14+dfsg-0+deb8u11", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-doc", ver:"2:4.2.14+dfsg-0+deb8u11", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-dsdb-modules", ver:"2:4.2.14+dfsg-0+deb8u11", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-libs", ver:"2:4.2.14+dfsg-0+deb8u11", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-testsuite", ver:"2:4.2.14+dfsg-0+deb8u11", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-vfs-modules", ver:"2:4.2.14+dfsg-0+deb8u11", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"smbclient", ver:"2:4.2.14+dfsg-0+deb8u11", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"winbind", ver:"2:4.2.14+dfsg-0+deb8u11", rls:"DEB8"))) {
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

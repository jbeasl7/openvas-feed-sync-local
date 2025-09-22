# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.890977");
  script_cve_id("CVE-2014-2015", "CVE-2015-4680", "CVE-2017-9148");
  script_tag(name:"creation_date", value:"2018-01-28 23:00:00 +0000 (Sun, 28 Jan 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-09 16:22:00 +0000 (Fri, 09 Jun 2017)");

  script_name("Debian: Security Advisory (DLA-977-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-977-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/DLA-977-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'freeradius' package(s) announced via the DLA-977-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues were discovered in FreeRADIUS, a high-performance and highly configurable RADIUS server.

CVE-2014-2015

A stack-based buffer overflow was found in the normify function in the rlm_pap module, which can be attacked by existing users to cause denial of service or other issues.

CVE-2015-4680

It was discovered that freeradius failed to check revocation of intermediate CA certificates, thus accepting client certificates issued by revoked certificates from intermediate CAs.

Note that to enable checking of intermediate CA certificates, it is necessary to enable the check_all_crl option of the EAP TLS section in eap.conf. This is only necessary for servers using certificates signed by intermediate CAs. Servers that use self-signed CAs are unaffected.

CVE-2017-9148

The TLS session cache fails to reliably prevent resumption of an unauthenticated session, which allows remote attackers (such as malicious 802.1X supplicants) to bypass authentication via PEAP or TTLS.

For Debian 7 Wheezy, these problems have been fixed in version 2.1.12+dfsg-1.2+deb7u1.

We recommend that you upgrade your freeradius packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'freeradius' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"freeradius", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-common", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-dbg", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-dialupadmin", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-iodbc", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-krb5", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-ldap", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-mysql", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-postgresql", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-utils", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreeradius-dev", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreeradius2", ver:"2.1.12+dfsg-1.2+deb7u1", rls:"DEB7"))) {
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

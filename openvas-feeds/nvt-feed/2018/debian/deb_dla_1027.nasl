# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891027");
  script_cve_id("CVE-2017-11103");
  script_tag(name:"creation_date", value:"2018-02-04 23:00:00 +0000 (Sun, 04 Feb 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-21 18:19:04 +0000 (Fri, 21 Jul 2017)");

  script_name("Debian: Security Advisory (DLA-1027-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-1027-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/DLA-1027-1");
  script_xref(name:"URL", value:"https://orpheus-lyre.info/");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'heimdal' package(s) announced via the DLA-1027-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jeffrey Altman, Viktor Duchovni and Nico Williams identified a mutual authentication bypass vulnerability in Heimdal Kerberos. Also known as Orpheus' Lyre, this vulnerability could be used by an attacker to mount a service impersonation attack on the client if he's on the network path between the client and the service.

More details can be found on the vulnerability website ([link moved to references]).

For Debian 7 Wheezy, these problems have been fixed in version 1.6~git20120403+dfsg1-2+deb7u1.

We recommend that you upgrade your heimdal packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'heimdal' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-clients", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-clients-x", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-dbg", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-dev", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-docs", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-kcm", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-kdc", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-multidev", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-servers", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-servers-x", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libasn1-8-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgssapi3-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhcrypto4-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhdb9-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libheimbase1-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libheimntlm0-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhx509-5-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkadm5clnt7-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkadm5srv8-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkafs0-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkdc2-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5-26-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libotp0-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroken18-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsl0-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwind0-heimdal", ver:"1.6~git20120403+dfsg1-2+deb7u1", rls:"DEB7"))) {
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

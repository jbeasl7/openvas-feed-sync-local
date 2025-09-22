# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704455");
  script_cve_id("CVE-2018-16860", "CVE-2019-12098");
  script_tag(name:"creation_date", value:"2019-06-05 02:00:07 +0000 (Wed, 05 Jun 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-12 02:28:31 +0000 (Mon, 12 Aug 2019)");

  script_name("Debian: Security Advisory (DSA-4455-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4455-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4455-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4455");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2018-16860.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/heimdal");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'heimdal' package(s) announced via the DSA-4455-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Heimdal, an implementation of Kerberos 5 that aims to be compatible with MIT Kerberos.

CVE-2018-16860

Isaac Boukris and Andrew Bartlett discovered that Heimdal was susceptible to man-in-the-middle attacks caused by incomplete checksum validation. Details on the issue can be found in the Samba advisory at [link moved to references].

CVE-2019-12098

It was discovered that failure of verification of the PA-PKINIT-KX key exchange client-side could permit to perform man-in-the-middle attack.

For the stable distribution (stretch), these problems have been fixed in version 7.1.0+dfsg-13+deb9u3.

We recommend that you upgrade your heimdal packages.

For the detailed security status of heimdal please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'heimdal' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-clients", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-dbg", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-dev", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-docs", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-kcm", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-kdc", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-multidev", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-servers", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libasn1-8-heimdal", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgssapi3-heimdal", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhcrypto4-heimdal", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhdb9-heimdal", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libheimbase1-heimdal", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libheimntlm0-heimdal", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhx509-5-heimdal", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkadm5clnt7-heimdal", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkadm5srv8-heimdal", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkafs0-heimdal", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkdc2-heimdal", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5-26-heimdal", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libotp0-heimdal", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libroken18-heimdal", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsl0-heimdal", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwind0-heimdal", ver:"7.1.0+dfsg-13+deb9u3", rls:"DEB9"))) {
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

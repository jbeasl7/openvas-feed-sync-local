# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703398");
  script_cve_id("CVE-2015-8023");
  script_tag(name:"creation_date", value:"2015-11-15 23:00:00 +0000 (Sun, 15 Nov 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-3398-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3398-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3398-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3398");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'strongswan' package(s) announced via the DSA-3398-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tobias Brunner found an authentication bypass vulnerability in strongSwan, an IKE/IPsec suite.

Due to insufficient validation of its local state the server implementation of the EAP-MSCHAPv2 protocol in the eap-mschapv2 plugin can be tricked into successfully concluding the authentication without providing valid credentials.

It's possible to recognize such attacks by looking at the server logs. The following log message would be seen during the client authentication:

EAP method EAP_MSCHAPV2 succeeded, no MSK established

For the oldstable distribution (wheezy), this problem has been fixed in version 4.5.2-1.5+deb7u8.

For the stable distribution (jessie), this problem has been fixed in version 5.2.1-6+deb8u2.

For the testing distribution (stretch), this problem has been fixed in version 5.3.3-3.

For the unstable distribution (sid), this problem has been fixed in version 5.3.3-3.

We recommend that you upgrade your strongswan packages.");

  script_tag(name:"affected", value:"'strongswan' package(s) on Debian 7, Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libstrongswan", ver:"4.5.2-1.5+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan", ver:"4.5.2-1.5+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan-dbg", ver:"4.5.2-1.5+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan-ikev1", ver:"4.5.2-1.5+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan-ikev2", ver:"4.5.2-1.5+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan-nm", ver:"4.5.2-1.5+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan-starter", ver:"4.5.2-1.5+deb7u8", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"charon-cmd", ver:"5.2.1-6+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcharon-extra-plugins", ver:"5.2.1-6+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libstrongswan", ver:"5.2.1-6+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libstrongswan-extra-plugins", ver:"5.2.1-6+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libstrongswan-standard-plugins", ver:"5.2.1-6+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan", ver:"5.2.1-6+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan-charon", ver:"5.2.1-6+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan-dbg", ver:"5.2.1-6+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan-ike", ver:"5.2.1-6+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan-ikev1", ver:"5.2.1-6+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan-ikev2", ver:"5.2.1-6+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan-libcharon", ver:"5.2.1-6+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan-nm", ver:"5.2.1-6+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan-starter", ver:"5.2.1-6+deb8u2", rls:"DEB8"))) {
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

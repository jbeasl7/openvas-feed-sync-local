# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840504");
  script_cve_id("CVE-2009-3555");
  script_tag(name:"creation_date", value:"2010-09-27 06:14:44 +0000 (Mon, 27 Sep 2010)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-990-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|6\.06\ LTS|8\.04\ LTS|9\.04|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-990-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-990-2");
  script_xref(name:"URL", value:"http://httpd.apache.org/docs/2.2/mod/mod_ssl.html#sslinsecurerenegotiation");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-990-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-860-1 introduced a partial workaround to Apache that disabled client
initiated TLS renegotiation in order to mitigate CVE-2009-3555. USN-990-1
introduced the new RFC5746 renegotiation extension in openssl, and
completely resolves the issue.

After updating openssl, an Apache server will allow both patched and
unpatched web browsers to connect, but unpatched browsers will not be able
to renegotiate. This update introduces the new SSLInsecureRenegotiation
directive for Apache that may be used to re-enable insecure renegotiations
with unpatched web browsers. For more information, please refer to:
[link moved to references]

Original advisory details:

 Marsh Ray and Steve Dispensa discovered a flaw in the TLS and SSLv3
 protocols. If an attacker could perform a machine-in-the-middle attack at the
 start of a TLS connection, the attacker could inject arbitrary content at
 the beginning of the user's session. This update adds backported support
 for the new RFC5746 renegotiation extension and will use it when both the
 client and the server support it.");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.04, Ubuntu 9.10, Ubuntu 10.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.14-5ubuntu8.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2-common", ver:"2.0.55-4ubuntu2.11", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.8-1ubuntu0.18", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.04") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.11-2ubuntu2.7", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.12-1ubuntu2.3", rls:"UBUNTU9.10"))) {
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

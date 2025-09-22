# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57481");
  script_cve_id("CVE-2006-2937", "CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4343");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1185-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1185-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-1185-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1185");
  script_xref(name:"URL", value:"https://www.niscc.gov.uk");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl' package(s) announced via the DSA-1185-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The fix used to correct CVE-2006-2940 introduced code that could lead to the use of uninitialized memory. Such use is likely to cause the application using the openssl library to crash, and has the potential to allow an attacker to cause the execution of arbitrary code. For reference please find below the original advisory text:

Multiple vulnerabilities have been discovered in the OpenSSL cryptographic software package that could allow an attacker to launch a denial of service attack by exhausting system resources or crashing processes on a victim's computer.

CVE-2006-2937

Dr S N Henson of the OpenSSL core team and Open Network Security recently developed an ASN1 test suite for NISCC ([link moved to references]). When the test suite was run against OpenSSL two denial of service vulnerabilities were discovered.

During the parsing of certain invalid ASN1 structures an error condition is mishandled. This can result in an infinite loop which consumes system memory.

Any code which uses OpenSSL to parse ASN1 data from untrusted sources is affected. This includes SSL servers which enable client authentication and S/MIME applications.

CVE-2006-3738

Tavis Ormandy and Will Drewry of the Google Security Team discovered a buffer overflow in SSL_get_shared_ciphers utility function, used by some applications such as exim and mysql. An attacker could send a list of ciphers that would overrun a buffer.

CVE-2006-4343

Tavis Ormandy and Will Drewry of the Google Security Team discovered a possible DoS in the sslv2 client code. Where a client application uses OpenSSL to make a SSLv2 connection to a malicious server that server could cause the client to crash.

CVE-2006-2940

Dr S N Henson of the OpenSSL core team and Open Network Security recently developed an ASN1 test suite for NISCC ([link moved to references]). When the test suite was run against OpenSSL a DoS was discovered.

Certain types of public key can take disproportionate amounts of time to process. This could be used by an attacker in a denial of service attack.

For the stable distribution (sarge) these problems have been fixed in version 0.9.7e-3sarge4.

For the unstable and testing distributions (sid and etch, respectively), these problems will be fixed in version 0.9.7k-3 of the openssl097 compatibility libraries, and version 0.9.8c-3 of the openssl package.

We recommend that you upgrade your openssl package. Note that services linking against the openssl shared libraries will need to be restarted. Common examples of such services include most Mail Transport Agents, SSH servers, and web servers.");

  script_tag(name:"affected", value:"'openssl' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto0.9.7-udeb", ver:"0.9.7e-3sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.7e-3sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl0.9.7", ver:"0.9.7e-3sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"0.9.7e-3sarge4", rls:"DEB3.1"))) {
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

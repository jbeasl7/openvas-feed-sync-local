# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840527");
  script_cve_id("CVE-2009-3555", "CVE-2010-3541", "CVE-2010-3548", "CVE-2010-3549", "CVE-2010-3551", "CVE-2010-3553", "CVE-2010-3554", "CVE-2010-3557", "CVE-2010-3561", "CVE-2010-3562", "CVE-2010-3564", "CVE-2010-3565", "CVE-2010-3566", "CVE-2010-3567", "CVE-2010-3568", "CVE-2010-3569", "CVE-2010-3573", "CVE-2010-3574");
  script_tag(name:"creation_date", value:"2010-11-04 11:09:38 +0000 (Thu, 04 Nov 2010)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1010-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|8\.04\ LTS|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1010-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1010-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-6, openjdk-6b18' package(s) announced via the USN-1010-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marsh Ray and Steve Dispensa discovered a flaw in the TLS and
SSLv3 protocols. If an attacker could perform a machine-in-the-middle
attack at the start of a TLS connection, the attacker could inject
arbitrary content at the beginning of the user's session. USN-923-1
disabled SSL/TLS renegotiation by default, this update implements
the TLS Renegotiation Indication Extension as defined in RFC 5746,
and thus supports secure renegotiation between updated clients and
servers. (CVE-2009-3555)

It was discovered that the HttpURLConnection class did not validate
request headers set by java applets, which could allow an attacker to
trigger actions otherwise not allowed to HTTP clients. (CVE-2010-3541)

It was discovered that JNDI could leak information that would allow an
attacker to access information about otherwise-protected internal
network names. (CVE-2010-3548)

It was discovered that HttpURLConnection improperly handled the
'chunked' transfer encoding method, which could allow attackers to
conduct HTTP response splitting attacks. (CVE-2010-3549)

It was discovered that the NetworkInterface class improperly
checked the network 'connect' permissions for local network
addresses. This could allow an attacker to read local network
addresses. (CVE-2010-3551)

It was discovered that UIDefault.ProxyLazyValue had unsafe reflection
usage, allowing an attacker to create objects. (CVE-2010-3553)

It was discovered that multiple flaws in the CORBA reflection
implementation could allow an attacker to execute arbitrary code by
misusing permissions granted to certain system objects. (CVE-2010-3554)

It was discovered that unspecified flaws in the Swing library could
allow untrusted applications to modify the behavior and state of
certain JDK classes. (CVE-2010-3557)

It was discovered that the privileged accept method of the ServerSocket
class in the CORBA implementation allowed it to receive connections
from any host, instead of just the host of the current connection.
An attacker could use this flaw to bypass restrictions defined by
network permissions. (CVE-2010-3561)

It was discovered that there exists a double free in java's
indexColorModel that could allow an attacker to cause an applet
or application to crash, or possibly execute arbitrary code
with the privilege of the user running the java applet or
application. (CVE-2010-3562)

It was discovered that the Kerberos implementation improperly checked
AP-REQ requests, which could allow an attacker to cause a denial of
service against the receiving JVM. (CVE-2010-3564)

It was discovered that improper checks of unspecified image metadata in
JPEGImageWriter.writeImage of the imageio API could allow an attacker
to execute arbitrary code with the privileges of the user running a
java applet or application. (CVE-2010-3565)

It was discovered that an unspecified vulnerability in the ICC
profile handling code could allow an attacker to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'openjdk-6, openjdk-6b18' package(s) on Ubuntu 8.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b18-1.8.2-4ubuntu2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b18-1.8.2-4ubuntu2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b18-1.8.2-4ubuntu2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b18-1.8.2-4ubuntu2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b18-1.8.2-4ubuntu1", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b18-1.8.2-4ubuntu1", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b18-1.8.2-4ubuntu1", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b18-1.8.2-4ubuntu1", rls:"UBUNTU10.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b18-1.8.2-4ubuntu1~8.04.1", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b18-1.8.2-4ubuntu1~8.04.1", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b18-1.8.2-4ubuntu1~8.04.1", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b18-1.8.2-4ubuntu1~8.04.1", rls:"UBUNTU8.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b18-1.8.2-4ubuntu1~9.10.1", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b18-1.8.2-4ubuntu1~9.10.1", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b18-1.8.2-4ubuntu1~9.10.1", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b18-1.8.2-4ubuntu1~9.10.1", rls:"UBUNTU9.10"))) {
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

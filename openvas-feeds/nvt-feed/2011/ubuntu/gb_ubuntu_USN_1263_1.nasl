# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840805");
  script_cve_id("CVE-2011-3377", "CVE-2011-3389", "CVE-2011-3521", "CVE-2011-3544", "CVE-2011-3547", "CVE-2011-3548", "CVE-2011-3551", "CVE-2011-3552", "CVE-2011-3553", "CVE-2011-3554", "CVE-2011-3556", "CVE-2011-3557", "CVE-2011-3558", "CVE-2011-3560");
  script_tag(name:"creation_date", value:"2011-11-18 04:16:15 +0000 (Fri, 18 Nov 2011)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 14:29:45 +0000 (Wed, 24 Jul 2024)");

  script_name("Ubuntu: Security Advisory (USN-1263-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|11\.04|11\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1263-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1263-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icedtea-web, openjdk-6, openjdk-6b18' package(s) announced via the USN-1263-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Deepak Bhole discovered a flaw in the Same Origin Policy (SOP)
implementation in the IcedTea web browser plugin. This could allow a
remote attacker to open connections to certain hosts that should
not be permitted. (CVE-2011-3377)

Juliano Rizzo and Thai Duong discovered that the block-wise AES
encryption algorithm block-wise as used in TLS/SSL was vulnerable to
a chosen-plaintext attack. This could allow a remote attacker to view
confidential data. (CVE-2011-3389)

It was discovered that a type confusion flaw existed in the in
the Internet Inter-Orb Protocol (IIOP) deserialization code. A
remote attacker could use this to cause an untrusted application
or applet to execute arbitrary code by deserializing malicious
input. (CVE-2011-3521)

It was discovered that the Java scripting engine did not perform
SecurityManager checks. This could allow a remote attacker to cause
an untrusted application or applet to execute arbitrary code with
the full privileges of the JVM. (CVE-2011-3544)

It was discovered that the InputStream class used a global buffer to
store input bytes skipped. An attacker could possibly use this to gain
access to sensitive information. (CVE-2011-3547)

It was discovered that a vulnerability existed in the AWTKeyStroke
class. A remote attacker could cause an untrusted application or applet
to execute arbitrary code. (CVE-2011-3548)

It was discovered that an integer overflow vulnerability existed
in the TransformHelper class in the Java2D implementation. A remote
attacker could use this cause a denial of service via an application
or applet crash or possibly execute arbitrary code. (CVE-2011-3551)

It was discovered that the default number of available UDP sockets for
applications running under SecurityManager restrictions was set too
high. A remote attacker could use this with a malicious application or
applet exhaust the number of available UDP sockets to cause a denial
of service for other applets or applications running within the same
JVM. (CVE-2011-3552)

It was discovered that Java API for XML Web Services (JAX-WS) could
incorrectly expose a stack trace. A remote attacker could potentially
use this to gain access to sensitive information. (CVE-2011-3553)

It was discovered that the unpacker for pack200 JAR files did not
sufficiently check for errors. An attacker could cause a denial of
service or possibly execute arbitrary code through a specially crafted
pack200 JAR file. (CVE-2011-3554)

It was discovered that the RMI registration implementation did not
properly restrict privileges of remotely executed code. A remote
attacker could use this to execute code with elevated privileges.
(CVE-2011-3556, CVE-2011-3557)

It was discovered that the HotSpot VM could be made to crash, allowing
an attacker to cause a denial of service or possibly leak sensitive
information. (CVE-2011-3558)

It was discovered that the HttpsURLConnection class did not
properly ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'icedtea-web, openjdk-6, openjdk-6b18' package(s) on Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04, Ubuntu 11.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b20-1.9.10-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b20-1.9.10-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-demo", ver:"6b20-1.9.10-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b20-1.9.10-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b20-1.9.10-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b20-1.9.10-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b20-1.9.10-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b20-1.9.10-0ubuntu1~10.10.2", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-demo", ver:"6b20-1.9.10-0ubuntu1~10.10.2", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b20-1.9.10-0ubuntu1~10.10.2", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b20-1.9.10-0ubuntu1~10.10.2", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b20-1.9.10-0ubuntu1~10.10.2", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b20-1.9.10-0ubuntu1~10.10.2", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b20-1.9.10-0ubuntu1~10.10.2", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b22-1.10.4-0ubuntu1~11.04.1", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-6-jre-jamvm", ver:"6b22-1.10.4-0ubuntu1~11.04.1", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-netx", ver:"1.1.1-0ubuntu1~11.04.2", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-plugin", ver:"1.1.1-0ubuntu1~11.04.2", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b22-1.10.4-0ubuntu1~11.04.1", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b22-1.10.4-0ubuntu1~11.04.1", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b22-1.10.4-0ubuntu1~11.04.1", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b22-1.10.4-0ubuntu1~11.04.1", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b23~pre11-0ubuntu1.11.10", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-6-jre-jamvm", ver:"6b23~pre11-0ubuntu1.11.10", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-netx", ver:"1.1.3-1ubuntu1.1", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-plugin", ver:"1.1.3-1ubuntu1.1", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b23~pre11-0ubuntu1.11.10", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b23~pre11-0ubuntu1.11.10", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b23~pre11-0ubuntu1.11.10", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b23~pre11-0ubuntu1.11.10", rls:"UBUNTU11.10"))) {
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

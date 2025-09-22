# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63797");
  script_cve_id("CVE-2006-2426", "CVE-2009-0581", "CVE-2009-0723", "CVE-2009-0733", "CVE-2009-0793", "CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1097", "CVE-2009-1098", "CVE-2009-1101");
  script_tag(name:"creation_date", value:"2009-04-15 20:11:00 +0000 (Wed, 15 Apr 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1769-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1769-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1769-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1769");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openjdk-6' package(s) announced via the DSA-1769-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been identified in OpenJDK, an implementation of the Java SE platform.

CVE-2006-2426

Creation of large, temporary fonts could use up available disk space, leading to a denial of service condition.

CVE-2009-0581 / CVE-2009-0723 / CVE-2009-0733 / CVE-2009-0793 Several vulnerabilities existed in the embedded LittleCMS library, exploitable through crafted images: a memory leak, resulting in a denial of service condition (CVE-2009-0581), heap-based buffer overflows, potentially allowing arbitrary code execution (CVE-2009-0723, CVE-2009-0733), and a null-pointer dereference, leading to denial of service (CVE-2009-0793).

CVE-2009-1093

The LDAP server implementation (in com.sun.jdni.ldap) did not properly close sockets if an error was encountered, leading to a denial-of-service condition.

CVE-2009-1094

The LDAP client implementation (in com.sun.jdni.ldap) allowed malicious LDAP servers to execute arbitrary code on the client.

CVE-2009-1101

The HTTP server implementation (sun.net.httpserver) contained an unspecified denial of service vulnerability.

CVE-2009-1095 / CVE-2009-1096 / CVE-2009-1097 / CVE-2009-1098 Several issues in Java Web Start have been addressed. The Debian packages currently do not support Java Web Start, so these issues are not directly exploitable, but the relevant code has been updated nevertheless.

For the stable distribution (lenny), these problems have been fixed in version 9.1+lenny2.

We recommend that you upgrade your openjdk-6 packages.");

  script_tag(name:"affected", value:"'openjdk-6' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-dbg", ver:"6b11-9.1+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-demo", ver:"6b11-9.1+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-doc", ver:"6b11-9.1+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b11-9.1+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b11-9.1+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b11-9.1+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b11-9.1+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-source", ver:"6b11-9.1+lenny2", rls:"DEB5"))) {
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

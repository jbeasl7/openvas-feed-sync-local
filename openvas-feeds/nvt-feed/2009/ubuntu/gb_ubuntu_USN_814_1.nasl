# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64654");
  script_cve_id("CVE-2009-0217", "CVE-2009-1896", "CVE-2009-2475", "CVE-2009-2476", "CVE-2009-2625", "CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2674", "CVE-2009-2675", "CVE-2009-2676", "CVE-2009-2689", "CVE-2009-2690");
  script_tag(name:"creation_date", value:"2009-08-17 14:54:45 +0000 (Mon, 17 Aug 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-814-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(8\.10|9\.04)");

  script_xref(name:"Advisory-ID", value:"USN-814-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-814-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-6' package(s) announced via the USN-814-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the XML HMAC signature system did not
correctly check certain lengths. If an attacker sent a truncated
HMAC, it could bypass authentication, leading to potential privilege
escalation. (CVE-2009-0217)

It was discovered that JAR bundles would appear signed if only one element
was signed. If a user were tricked into running a malicious Java applet, a
remote attacker could exploit this to gain access to private information and
potentially run untrusted code. (CVE-2009-1896)

It was discovered that certain variables could leak information. If a
user were tricked into running a malicious Java applet, a remote attacker
could exploit this to gain access to private information and potentially
run untrusted code. (CVE-2009-2475, CVE-2009-2690)

A flaw was discovered the OpenType checking. If a user were tricked
into running a malicious Java applet, a remote attacker could bypass
access restrictions. (CVE-2009-2476)

It was discovered that the XML processor did not correctly check
recursion. If a user or automated system were tricked into processing
a specially crafted XML, the system could crash, leading to a denial of
service. (CVE-2009-2625)

It was discovered that the Java audio subsystem did not correctly validate
certain parameters. If a user were tricked into running an untrusted
applet, a remote attacker could read system properties. (CVE-2009-2670)

Multiple flaws were discovered in the proxy subsystem. If a user
were tricked into running an untrusted applet, a remote attacker could
discover local user names, obtain access to sensitive information, or
bypass socket restrictions, leading to a loss of privacy. (CVE-2009-2671,
CVE-2009-2672, CVE-2009-2673)

Flaws were discovered in the handling of JPEG images, Unpack200 archives,
and JDK13Services. If a user were tricked into running an untrusted
applet, a remote attacker could load a specially crafted file that would
bypass local file access protections and run arbitrary code with user
privileges. (CVE-2009-2674, CVE-2009-2675, CVE-2009-2676, CVE-2009-2689)");

  script_tag(name:"affected", value:"'openjdk-6' package(s) on Ubuntu 8.10, Ubuntu 9.04.");

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

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b12-0ubuntu6.5", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b12-0ubuntu6.5", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b12-0ubuntu6.5", rls:"UBUNTU8.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b14-1.4.1-0ubuntu11", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b14-1.4.1-0ubuntu11", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b14-1.4.1-0ubuntu11", rls:"UBUNTU9.04"))) {
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

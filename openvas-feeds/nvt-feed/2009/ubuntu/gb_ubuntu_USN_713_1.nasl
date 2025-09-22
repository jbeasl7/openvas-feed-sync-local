# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63308");
  script_cve_id("CVE-2008-5347", "CVE-2008-5348", "CVE-2008-5349", "CVE-2008-5350", "CVE-2008-5351", "CVE-2008-5352", "CVE-2008-5353", "CVE-2008-5354", "CVE-2008-5358", "CVE-2008-5359", "CVE-2008-5360");
  script_tag(name:"creation_date", value:"2009-02-02 22:28:24 +0000 (Mon, 02 Feb 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-713-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU8\.10");

  script_xref(name:"Advisory-ID", value:"USN-713-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-713-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-6' package(s) announced via the USN-713-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Java did not correctly handle untrusted applets.
If a user were tricked into running a malicious applet, a remote attacker
could gain user privileges, or list directory contents. (CVE-2008-5347,
CVE-2008-5350)

It was discovered that Kerberos authentication and RSA public key
processing were not correctly handled in Java. A remote attacker
could exploit these flaws to cause a denial of service. (CVE-2008-5348,
CVE-2008-5349)

It was discovered that Java accepted UTF-8 encodings that might be
handled incorrectly by certain applications. A remote attacker could
bypass string filters, possible leading to other exploits. (CVE-2008-5351)

Overflows were discovered in Java JAR processing. If a user or
automated system were tricked into processing a malicious JAR file,
a remote attacker could crash the application, leading to a denial of
service. (CVE-2008-5352, CVE-2008-5354)

It was discovered that Java calendar objects were not unserialized safely.
If a user or automated system were tricked into processing a specially
crafted calendar object, a remote attacker could execute arbitrary code
with user privileges. (CVE-2008-5353)

It was discovered that the Java image handling code could lead to memory
corruption. If a user or automated system were tricked into processing
a specially crafted image, a remote attacker could crash the application,
leading to a denial of service. (CVE-2008-5358, CVE-2008-5359)

It was discovered that temporary files created by Java had predictable
names. If a user or automated system were tricked into processing a
specially crafted JAR file, a remote attacker could overwrite sensitive
information. (CVE-2008-5360)");

  script_tag(name:"affected", value:"'openjdk-6' package(s) on Ubuntu 8.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b12-0ubuntu6.1", rls:"UBUNTU8.10"))) {
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

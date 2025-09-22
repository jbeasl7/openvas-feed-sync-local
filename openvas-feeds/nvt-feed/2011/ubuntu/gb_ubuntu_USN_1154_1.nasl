# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840683");
  script_cve_id("CVE-2011-0815", "CVE-2011-0822", "CVE-2011-0862", "CVE-2011-0864", "CVE-2011-0865", "CVE-2011-0867", "CVE-2011-0868", "CVE-2011-0869", "CVE-2011-0870", "CVE-2011-0871", "CVE-2011-0872");
  script_tag(name:"creation_date", value:"2011-06-24 14:46:35 +0000 (Fri, 24 Jun 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1154-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|11\.04)");

  script_xref(name:"Advisory-ID", value:"USN-1154-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1154-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-6, openjdk-6b18' package(s) announced via the USN-1154-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a heap overflow in the AWT FileDialog.show()
method could allow an attacker to cause a denial of service through an
application crash or possibly execute arbitrary code. (CVE-2011-0815)

It was discovered that integer overflows in the JPEGImageReader
readImage() function and the SunLayoutEngine nativeLayout() function
could allow an attacker to cause a denial of service through an
application crash or possibly execute arbitrary code. (CVE-2011-0822,
CVE-2011-0862)

It was discovered that memory corruption could occur when interpreting
bytecode in the HotSpot VM. This could allow an attacker to cause a
denial of service through an application crash or possibly execute
arbitrary code. (CVE-2011-0864)

It was discovered that the deserialization code allowed the creation
of mutable SignedObjects. This could allow an attacker to possibly
execute code with elevated privileges. (CVE-2011-0865)

It was discovered that the toString method in the NetworkInterface
class would reveal multiple addresses if they were bound to the
interface. This could give an attacker more information about the
networking environment. (CVE-2011-0867)

It was discovered that the Java 2D code to transform an image with a
scale close to 0 could trigger an integer overflow. This could allow
an attacker to cause a denial of service through an application crash
or possibly execute arbitrary code. (CVE-2011-0868)

It was discovered that the SOAP with Attachments API for Java (SAAJ)
implementation allowed the modification of proxy settings via
unprivileged SOAP messages. (CVE-2011-0869, CVE-2011-0870)

It was the discovered that the Swing ImageIcon class created
MediaTracker objects that potentially leaked privileged
ApplicationContexts. This could possibly allow an attacker access to
restricted resources or services. (CVE-2011-0871)

It was discovered that non-blocking sockets marked as not urgent could
still get selected for read operations. This could allow an attacker
to cause a denial of service. (CVE-2011-0872)");

  script_tag(name:"affected", value:"'openjdk-6, openjdk-6b18' package(s) on Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b20-1.9.8-0ubuntu1~10.04.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b20-1.9.8-0ubuntu1~10.04.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b20-1.9.8-0ubuntu1~10.04.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b20-1.9.8-0ubuntu1~10.04.1", rls:"UBUNTU10.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b20-1.9.8-0ubuntu1~10.10.1", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b20-1.9.8-0ubuntu1~10.10.1", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b20-1.9.8-0ubuntu1~10.10.1", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b20-1.9.8-0ubuntu1~10.10.1", rls:"UBUNTU10.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b22-1.10.2-0ubuntu1~11.04.1", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b22-1.10.2-0ubuntu1~11.04.1", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b22-1.10.2-0ubuntu1~11.04.1", rls:"UBUNTU11.04"))) {
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

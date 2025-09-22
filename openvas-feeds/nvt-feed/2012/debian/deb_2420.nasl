# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71148");
  script_cve_id("CVE-2011-3377", "CVE-2011-3563", "CVE-2011-5035", "CVE-2012-0497", "CVE-2012-0501", "CVE-2012-0502", "CVE-2012-0503", "CVE-2012-0505", "CVE-2012-0506", "CVE-2012-0507");
  script_tag(name:"creation_date", value:"2012-03-12 15:32:55 +0000 (Mon, 12 Mar 2012)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2420-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2420-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2420-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2420");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openjdk-6' package(s) announced via the DSA-2420-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in OpenJDK, an implementation of the Oracle Java platform.

CVE-2011-3377

The IcedTea browser plugin included in the openjdk-6 package does not properly enforce the Same Origin Policy on web content served under a domain name which has a common suffix with the required domain name.

CVE-2011-3563

The Java Sound component did not properly check for array boundaries. A malicious input or an untrusted Java application or applet could use this flaw to cause Java Virtual Machine to crash or disclose portion of its memory.

CVE-2011-5035

The OpenJDK embedded web server did not guard against an excessive number of a request parameters, leading to a denial of service vulnerability involving hash collisions.

CVE-2012-0497

It was discovered that Java2D did not properly check graphics rendering objects before passing them to the native renderer. This could lead to JVM crash or Java sandbox bypass.

CVE-2012-0501

The ZIP central directory parser used by java.util.zip.ZipFile entered an infinite recursion in native code when processing a crafted ZIP file, leading to a denial of service.

CVE-2012-0502

A flaw was found in the AWT KeyboardFocusManager class that could allow untrusted Java applets to acquire keyboard focus and possibly steal sensitive information.

CVE-2012-0503

The java.util.TimeZone.setDefault() method lacked a security manager invocation, allowing an untrusted Java application or applet to set a new default time zone.

CVE-2012-0505

The Java serialization code leaked references to serialization exceptions, possibly leaking critical objects to untrusted code in Java applets and applications.

CVE-2012-0506

It was discovered that CORBA implementation in Java did not properly protect repository identifiers (that can be obtained using _ids() method) on certain Corba objects. This could have been used to perform modification of the data that should have been immutable.

CVE-2012-0507

The AtomicReferenceArray class implementation did not properly check if the array is of an expected Object[] type. A malicious Java application or applet could use this flaw to cause Java Virtual Machine to crash or bypass Java sandbox restrictions.

For the stable distribution (squeeze), these problems have been fixed in version 6b18-1.8.13-0+squeeze1.

For the testing distribution (wheezy) and the unstable distribution (sid), these problems have been fixed in version 6b24-1.11.1-1.

We recommend that you upgrade your openjdk-6 packages.");

  script_tag(name:"affected", value:"'openjdk-6' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b18-1.8.13-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b18-1.8.13-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-dbg", ver:"6b18-1.8.13-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-demo", ver:"6b18-1.8.13-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-doc", ver:"6b18-1.8.13-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b18-1.8.13-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b18-1.8.13-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b18-1.8.13-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b18-1.8.13-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b18-1.8.13-0+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-source", ver:"6b18-1.8.13-0+squeeze1", rls:"DEB6"))) {
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

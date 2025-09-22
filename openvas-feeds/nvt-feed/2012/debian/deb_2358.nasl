# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70571");
  script_cve_id("CVE-2011-0862", "CVE-2011-0864", "CVE-2011-0865", "CVE-2011-0867", "CVE-2011-0868", "CVE-2011-0869", "CVE-2011-0871", "CVE-2011-3389", "CVE-2011-3521", "CVE-2011-3544", "CVE-2011-3547", "CVE-2011-3548", "CVE-2011-3551", "CVE-2011-3552", "CVE-2011-3553", "CVE-2011-3554", "CVE-2011-3556", "CVE-2011-3557", "CVE-2011-3560");
  script_tag(name:"creation_date", value:"2012-02-11 07:33:46 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 14:29:45 +0000 (Wed, 24 Jul 2024)");

  script_name("Debian: Security Advisory (DSA-2358-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2358-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2358-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2358");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openjdk-6' package(s) announced via the DSA-2358-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in OpenJDK, an implementation of the Java platform. This combines the two previous openjdk-6 advisories, DSA-2311-1 and DSA-2356-1.

CVE-2011-0862

Integer overflow errors in the JPEG and font parser allow untrusted code (including applets) to elevate its privileges.

CVE-2011-0864

Hotspot, the just-in-time compiler in OpenJDK, mishandled certain byte code instructions, allowing untrusted code (including applets) to crash the virtual machine.

CVE-2011-0865

A race condition in signed object deserialization could allow untrusted code to modify signed content, apparently leaving its signature intact.

CVE-2011-0867

Untrusted code (including applets) could access information about network interfaces which was not intended to be public. (Note that the interface MAC address is still available to untrusted code.)

CVE-2011-0868

A float-to-long conversion could overflow, allowing untrusted code (including applets) to crash the virtual machine.

CVE-2011-0869

Untrusted code (including applets) could intercept HTTP requests by reconfiguring proxy settings through a SOAP connection.

CVE-2011-0871

Untrusted code (including applets) could elevate its privileges through the Swing MediaTracker code.

CVE-2011-3389

The TLS implementation does not guard properly against certain chosen-plaintext attacks when block ciphers are used in CBC mode.

CVE-2011-3521

The CORBA implementation contains a deserialization vulnerability in the IIOP implementation, allowing untrusted Java code (such as applets) to elevate its privileges.

CVE-2011-3544

The Java scripting engine lacks necessary security manager checks, allowing untrusted Java code (such as applets) to elevate its privileges.

CVE-2011-3547

The skip() method in java.io.InputStream uses a shared buffer, allowing untrusted Java code (such as applets) to access data that is skipped by other code.

CVE-2011-3548

The java.awt.AWTKeyStroke class contains a flaw which allows untrusted Java code (such as applets) to elevate its privileges.

CVE-2011-3551

The Java2D C code contains an integer overflow which results in a heap-based buffer overflow, potentially allowing untrusted Java code (such as applets) to elevate its privileges.

CVE-2011-3552

Malicious Java code can use up an excessive amount of UDP ports, leading to a denial of service.

CVE-2011-3553

JAX-WS enables stack traces for certain server responses by default, potentially leaking sensitive information.

CVE-2011-3554

JAR files in pack200 format are not properly checked for errors, potentially leading to arbitrary code execution when unpacking crafted pack200 files.

CVE-2011-3556

The RMI Registry server lacks access restrictions on certain methods, allowing a remote client to execute arbitrary code.

CVE-2011-3557

The RMI Registry server fails to properly restrict privileges of untrusted ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'openjdk-6' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-dbg", ver:"6b18-1.8.10-0~lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-demo", ver:"6b18-1.8.10-0~lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-doc", ver:"6b18-1.8.10-0~lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b18-1.8.10-0~lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b18-1.8.10-0~lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b18-1.8.10-0~lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b18-1.8.10-0~lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-source", ver:"6b18-1.8.10-0~lenny2", rls:"DEB5"))) {
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

# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702736");
  script_cve_id("CVE-2013-4206", "CVE-2013-4207", "CVE-2013-4208", "CVE-2013-4852");
  script_tag(name:"creation_date", value:"2013-08-10 22:00:00 +0000 (Sat, 10 Aug 2013)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2736-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2736-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/DSA-2736-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2736");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'putty' package(s) announced via the DSA-2736-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities where discovered in PuTTY, a Telnet/SSH client for X. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2013-4206

Mark Wooding discovered a heap-corrupting buffer underrun bug in the modmul function which performs modular multiplication. As the modmul function is called during validation of any DSA signature received by PuTTY, including during the initial key exchange phase, a malicious server could exploit this vulnerability before the client has received and verified a host key signature. An attack to this vulnerability can thus be performed by a man-in-the-middle between the SSH client and server, and the normal host key protections against man-in-the-middle attacks are bypassed.

CVE-2013-4207

It was discovered that non-coprime values in DSA signatures can cause a buffer overflow in the calculation code of modular inverses when verifying a DSA signature. Such a signature is invalid. This bug however applies to any DSA signature received by PuTTY, including during the initial key exchange phase and thus it can be exploited by a malicious server before the client has received and verified a host key signature.

CVE-2013-4208

It was discovered that private keys were left in memory after being used by PuTTY tools.

CVE-2013-4852

Gergely Eberhardt from SEARCH-LAB Ltd. discovered that PuTTY is vulnerable to an integer overflow leading to heap overflow during the SSH handshake before authentication due to improper bounds checking of the length parameter received from the SSH server. A remote attacker could use this vulnerability to mount a local denial of service attack by crashing the putty client.

Additionally this update backports some general proactive potentially security-relevant tightening from upstream.

For the oldstable distribution (squeeze), these problems have been fixed in version 0.60+2010-02-20-1+squeeze2. This update also provides a fix for CVE-2011-4607, which was fixed for stable already.

For the stable distribution (wheezy), these problems have been fixed in version 0.62-9+deb7u1.

For the unstable distribution (sid), these problems have been fixed in version 0.63-1.

We recommend that you upgrade your putty packages.");

  script_tag(name:"affected", value:"'putty' package(s) on Debian 6, Debian 7.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"pterm", ver:"0.60+2010-02-20-1+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"putty", ver:"0.60+2010-02-20-1+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"putty-doc", ver:"0.60+2010-02-20-1+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"putty-tools", ver:"0.60+2010-02-20-1+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"pterm", ver:"0.62-9+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"putty", ver:"0.62-9+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"putty-doc", ver:"0.62-9+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"putty-tools", ver:"0.62-9+deb7u1", rls:"DEB7"))) {
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

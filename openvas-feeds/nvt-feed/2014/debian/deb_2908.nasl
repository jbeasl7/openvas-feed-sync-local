# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702908");
  script_cve_id("CVE-2010-5298", "CVE-2014-0076");
  script_tag(name:"creation_date", value:"2014-04-16 22:00:00 +0000 (Wed, 16 Apr 2014)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2908-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2908-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2908-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2908");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl' package(s) announced via the DSA-2908-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in OpenSSL. The following Common Vulnerabilities and Exposures project ids identify them:

CVE-2010-5298

A read buffer can be freed even when it still contains data that is used later on, leading to a use-after-free. Given a race condition in a multi-threaded application it may permit an attacker to inject data from one connection into another or cause denial of service.

CVE-2014-0076

ECDSA nonces can be recovered through the Yarom/Benger FLUSH+RELOAD cache side-channel attack.

A third issue, with no CVE id, is the missing detection of the critical flag for the TSA extended key usage under certain cases.

Additionally, this update checks for more services that might need to be restarted after upgrades of libssl, corrects the detection of apache2 and postgresql, and adds support for the 'libraries/restart-without-asking' debconf configuration. This allows services to be restarted on upgrade without prompting.

The oldstable distribution (squeeze) is not affected by CVE-2010-5298 and it might be updated at a later time to address the remaining vulnerabilities.

For the stable distribution (wheezy), these problems have been fixed in version 1.0.1e-2+deb7u7.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 1.0.1g-3.

We recommend that you upgrade your openssl packages.");

  script_tag(name:"affected", value:"'openssl' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto1.0.0-udeb", ver:"1.0.1e-2+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl-dev", ver:"1.0.1e-2+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl-doc", ver:"1.0.1e-2+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1e-2+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0-dbg", ver:"1.0.1e-2+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.0.1e-2+deb7u7", rls:"DEB7"))) {
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

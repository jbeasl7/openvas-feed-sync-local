# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704065");
  script_cve_id("CVE-2017-3737", "CVE-2017-3738");
  script_tag(name:"creation_date", value:"2017-12-16 23:00:00 +0000 (Sat, 16 Dec 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-22 20:06:49 +0000 (Fri, 22 Dec 2017)");

  script_name("Debian: Security Advisory (DSA-4065-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4065-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-4065-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4065");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20171207.txt");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openssl1.0");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl1.0' package(s) announced via the DSA-4065-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in OpenSSL, a Secure Sockets Layer toolkit. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2017-3737

David Benjamin of Google reported that OpenSSL does not properly handle SSL_read() and SSL_write() while being invoked in an error state, causing data to be passed without being decrypted or encrypted directly from the SSL/TLS record layer.

CVE-2017-3738

It was discovered that OpenSSL contains an overflow bug in the AVX2 Montgomery multiplication procedure used in exponentiation with 1024-bit moduli.

Details can be found in the upstream advisory: [link moved to references]

For the stable distribution (stretch), these problems have been fixed in version 1.0.2l-2+deb9u2.

We recommend that you upgrade your openssl1.0 packages.

For the detailed security status of openssl1.0 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'openssl1.0' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto1.0.2-udeb", ver:"1.0.2l-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0-dev", ver:"1.0.2l-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.2", ver:"1.0.2l-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.2-udeb", ver:"1.0.2l-2+deb9u2", rls:"DEB9"))) {
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

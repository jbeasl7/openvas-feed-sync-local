# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703566");
  script_cve_id("CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2107", "CVE-2016-2108", "CVE-2016-2109");
  script_tag(name:"creation_date", value:"2016-05-02 22:00:00 +0000 (Mon, 02 May 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-06 12:32:16 +0000 (Fri, 06 May 2016)");

  script_name("Debian: Security Advisory (DSA-3566-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3566-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3566-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3566");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20160503.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl' package(s) announced via the DSA-3566-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in OpenSSL, a Secure Socket Layer toolkit.

CVE-2016-2105

Guido Vranken discovered that an overflow can occur in the function EVP_EncodeUpdate(), used for Base64 encoding, if an attacker can supply a large amount of data. This could lead to a heap corruption.

CVE-2016-2106

Guido Vranken discovered that an overflow can occur in the function EVP_EncryptUpdate() if an attacker can supply a large amount of data. This could lead to a heap corruption.

CVE-2016-2107

Juraj Somorovsky discovered a padding oracle in the AES CBC cipher implementation based on the AES-NI instruction set. This could allow an attacker to decrypt TLS traffic encrypted with one of the cipher suites based on AES CBC.

CVE-2016-2108

David Benjamin from Google discovered that two separate bugs in the ASN.1 encoder, related to handling of negative zero integer values and large universal tags, could lead to an out-of-bounds write.

CVE-2016-2109

Brian Carpenter discovered that when ASN.1 data is read from a BIO using functions such as d2i_CMS_bio(), a short invalid encoding can cause allocation of large amounts of memory potentially consuming excessive resources or exhausting memory.

Additional information about these issues can be found in the OpenSSL security advisory at [link moved to references]

For the stable distribution (jessie), these problems have been fixed in version 1.0.1k-3+deb8u5.

For the unstable distribution (sid), these problems have been fixed in version 1.0.2h-1.

We recommend that you upgrade your openssl packages.");

  script_tag(name:"affected", value:"'openssl' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto1.0.0-udeb", ver:"1.0.1k-3+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl-dev", ver:"1.0.1k-3+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl-doc", ver:"1.0.1k-3+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1k-3+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0-dbg", ver:"1.0.1k-3+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.0.1k-3+deb8u5", rls:"DEB8"))) {
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

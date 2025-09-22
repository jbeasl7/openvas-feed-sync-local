# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891518");
  script_cve_id("CVE-2018-0497", "CVE-2018-0498", "CVE-2018-9988", "CVE-2018-9989");
  script_tag(name:"creation_date", value:"2018-09-25 22:00:00 +0000 (Tue, 25 Sep 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-15 13:20:39 +0000 (Tue, 15 May 2018)");

  script_name("Debian: Security Advisory (DLA-1518-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1518-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1518-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'polarssl' package(s) announced via the DLA-1518-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in polarssl, a lightweight crypto and SSL/TLS library (nowadays continued under the name mbedtls) which could result in plain text recovery via side-channel attacks.

Two other minor vulnerabilities were discovered in polarssl which could result in arithmetic overflow errors.

CVE-2018-0497

As a protection against the Lucky Thirteen attack, the TLS code for CBC decryption in encrypt-then-MAC mode performs extra MAC calculations to compensate for variations in message size due to padding. The amount of extra MAC calculation to perform was based on the assumption that the bulk of the time is spent in processing 64-byte blocks, which is correct for most supported hashes but not for SHA-384. Correct the amount of extra work for SHA-384 (and SHA-512 which is currently not used in TLS, and MD2 although no one should care about that).

This is a regression fix for what CVE-2013-0169 had been fixed this.

CVE-2018-0498

The basis for the Lucky 13 family of attacks is for an attacker to be able to distinguish between (long) valid TLS-CBC padding and invalid TLS-CBC padding. Since our code sets padlen = 0 for invalid padding, the length of the input to the HMAC function gives information about that.

Information about this length (modulo the MD/SHA block size) can be deduced from how much MD/SHA padding (this is distinct from TLS-CBC padding) is used. If MD/SHA padding is read from a (static) buffer, a local attacker could get information about how much is used via a cache attack targeting that buffer.

Let's get rid of this buffer. Now the only buffer used is the internal MD/SHA one, which is always read fully by the process() function.

CVE-2018-9988

Prevent arithmetic overflow on bounds check and add bound check before signature length read in ssl_parse_server_key_exchange().

CVE-2018-9989

Prevent arithmetic overflow on bounds check and add bound check before length read in ssl_parse_server_psk_hint()

For Debian 8 Jessie, these problems have been fixed in version 1.3.9-2.1+deb8u4.

We recommend that you upgrade your polarssl packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'polarssl' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libpolarssl-dev", ver:"1.3.9-2.1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpolarssl-runtime", ver:"1.3.9-2.1+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpolarssl7", ver:"1.3.9-2.1+deb8u4", rls:"DEB8"))) {
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

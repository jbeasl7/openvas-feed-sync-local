# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703500");
  script_cve_id("CVE-2016-0702", "CVE-2016-0705", "CVE-2016-0797", "CVE-2016-0798", "CVE-2016-0799", "CVE-2016-2842");
  script_tag(name:"creation_date", value:"2016-03-08 07:07:52 +0000 (Tue, 08 Mar 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-04 18:30:22 +0000 (Fri, 04 Mar 2016)");

  script_name("Debian: Security Advisory (DSA-3500-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3500-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3500-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3500");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl' package(s) announced via the DSA-3500-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in OpenSSL, a Secure Socket Layer toolkit.

CVE-2016-0702

Yuval Yarom from the University of Adelaide and NICTA, Daniel Genkin from Technion and Tel Aviv University, and Nadia Heninger from the University of Pennsylvania discovered a side-channel attack which makes use of cache-bank conflicts on the Intel Sandy-Bridge microarchitecture. This could allow local attackers to recover RSA private keys.

CVE-2016-0705

Adam Langley from Google discovered a double free bug when parsing malformed DSA private keys. This could allow remote attackers to cause a denial of service or memory corruption in applications parsing DSA private keys received from untrusted sources.

CVE-2016-0797

Guido Vranken discovered an integer overflow in the BN_hex2bn and BN_dec2bn functions that can lead to a NULL pointer dereference and heap corruption. This could allow remote attackers to cause a denial of service or memory corruption in applications processing hex or dec data received from untrusted sources.

CVE-2016-0798

Emilia Kasper of the OpenSSL development team discovered a memory leak in the SRP database lookup code. To mitigate the memory leak, the seed handling in SRP_VBASE_get_by_user is now disabled even if the user has configured a seed. Applications are advised to migrate to the SRP_VBASE_get1_by_user function.

CVE-2016-0799, CVE-2016-2842 Guido Vranken discovered an integer overflow in the BIO_*printf functions that could lead to an OOB read when printing very long strings. Additionally the internal doapr_outch function can attempt to write to an arbitrary memory location in the event of a memory allocation failure. These issues will only occur on platforms where sizeof(size_t) > sizeof(int) like many 64 bit systems. This could allow remote attackers to cause a denial of service or memory corruption in applications that pass large amounts of untrusted data to the BIO_*printf functions.

Additionally the EXPORT and LOW ciphers were disabled since they could be used as part of the DROWN (CVE-2016-0800) and SLOTH (CVE-2015-7575) attacks, but note that the oldstable (wheezy) and stable (jessie) distributions are not affected by those attacks since the SSLv2 protocol has already been dropped in the openssl package version 1.0.0c-2.

For the oldstable distribution (wheezy), these problems have been fixed in version 1.0.1e-2+deb7u20.

For the stable distribution (jessie), these problems have been fixed in version 1.0.1k-3+deb8u4.

For the unstable distribution (sid), these problems will be fixed shortly.

We recommend that you upgrade your openssl packages.");

  script_tag(name:"affected", value:"'openssl' package(s) on Debian 7, Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto1.0.0-udeb", ver:"1.0.1e-2+deb7u20", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl-dev", ver:"1.0.1e-2+deb7u20", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl-doc", ver:"1.0.1e-2+deb7u20", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1e-2+deb7u20", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0-dbg", ver:"1.0.1e-2+deb7u20", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.0.1e-2+deb7u20", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto1.0.0-udeb", ver:"1.0.1k-3+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl-dev", ver:"1.0.1k-3+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl-doc", ver:"1.0.1k-3+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1k-3+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0-dbg", ver:"1.0.1k-3+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.0.1k-3+deb8u4", rls:"DEB8"))) {
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

# Copyright (C) 2015 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.850678");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2015-09-18 10:33:35 +0200 (Fri, 18 Sep 2015)");
  script_cve_id("CVE-2014-3570", "CVE-2014-3572", "CVE-2014-8176", "CVE-2014-8275", "CVE-2015-0205", "CVE-2015-0206", "CVE-2015-0209", "CVE-2015-0286", "CVE-2015-0287", "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-1788", "CVE-2015-1789", "CVE-2015-1790", "CVE-2015-1792", "CVE-2015-4000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:29:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for libressl (openSUSE-SU-2015:1277-1)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libressl'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libressl was updated to version 2.2.1 to fix 16 security issues.

  LibreSSL is a fork of OpenSSL. Because of that CVEs affecting OpenSSL
  often also affect LibreSSL.

  These security issues were fixed:

  - CVE-2014-3570: The BN_sqr implementation in OpenSSL before 0.9.8zd,
  1.0.0 before 1.0.0p, and 1.0.1 before 1.0.1k did not properly calculate
  the square of a BIGNUM value, which might make it easier for remote
  attackers to defeat cryptographic protection mechanisms via unspecified
  vectors, related to crypto/bn/asm/mips.pl, crypto/bn/asm/x86_64-gcc.c,
  and crypto/bn/bn_asm.c (bsc#912296).

  - CVE-2014-3572: The ssl3_get_key_exchange function in s3_clnt.c in
  OpenSSL before 0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1 before 1.0.1k
  allowed remote SSL servers to conduct ECDHE-to-ECDH downgrade attacks
  and trigger a loss of forward secrecy by omitting the ServerKeyExchange
  message (bsc#912015).

  - CVE-2015-1792: The do_free_upto function in crypto/cms/cms_smime.c in
  OpenSSL before 0.9.8zg, 1.0.0 before 1.0.0s, 1.0.1 before 1.0.1n, and
  1.0.2 before 1.0.2b allowed remote attackers to cause a denial of
  service (infinite loop) via vectors that trigger a NULL value of a BIO
  data structure, as demonstrated by an unrecognized X.660 OID for a hash
  function (bsc#934493).

  - CVE-2014-8275: OpenSSL before 0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1
  before 1.0.1k did not enforce certain constraints on certificate data,
  which allowed remote attackers to defeat a fingerprint-based
  certificate-blacklist protection mechanism by including crafted data
  within a certificate's unsigned portion, related to
  crypto/asn1/a_verify.c, crypto/dsa/dsa_asn1.c, crypto/ecdsa/ecs_vrf.c,
  and crypto/x509/x_all.c (bsc#912018).

  - CVE-2015-0209: Use-after-free vulnerability in the d2i_ECPrivateKey
  function in crypto/ec/ec_asn1.c in OpenSSL before 0.9.8zf, 1.0.0 before
  1.0.0r, 1.0.1 before 1.0.1m, and 1.0.2 before 1.0.2a might allowed
  remote attackers to cause a denial of service (memory corruption and
  application crash) or possibly have unspecified other impact via a
  malformed Elliptic Curve (EC) private-key file that is improperly
  handled during import (bsc#919648).

  - CVE-2015-1789: The X509_cmp_time function in crypto/x509/x509_vfy.c in
  OpenSSL before 0.9.8zg, 1.0.0 before 1.0.0s, 1.0.1 before 1.0.1n, and
  1.0.2 before 1.0.2b allowed remote attackers to cause a denial of
  service (out-of-bounds read and application crash) via a crafted length
  field in ASN1_TIME data, as demonstrated by an attack against a server
  that supports client authentication with a custom verific ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"libressl on openSUSE 13.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"openSUSE-SU", value:"2015:1277-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE13.2") {
  if(!isnull(res = isrpmvuln(pkg:"libcrypto34", rpm:"libcrypto34~2.2.1~2.3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcrypto34-debuginfo", rpm:"libcrypto34-debuginfo~2.2.1~2.3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libressl", rpm:"libressl~2.2.1~2.3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libressl-debuginfo", rpm:"libressl-debuginfo~2.2.1~2.3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libressl-debugsource", rpm:"libressl-debugsource~2.2.1~2.3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libressl-devel", rpm:"libressl-devel~2.2.1~2.3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssl33", rpm:"libssl33~2.2.1~2.3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssl33-debuginfo", rpm:"libssl33-debuginfo~2.2.1~2.3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtls4", rpm:"libtls4~2.2.1~2.3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtls4-debuginfo", rpm:"libtls4-debuginfo~2.2.1~2.3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcrypto34-32bit", rpm:"libcrypto34-32bit~2.2.1~2.3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcrypto34-debuginfo-32bit", rpm:"libcrypto34-debuginfo-32bit~2.2.1~2.3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libressl-devel-32bit", rpm:"libressl-devel-32bit~2.2.1~2.3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssl33-32bit", rpm:"libssl33-32bit~2.2.1~2.3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssl33-debuginfo-32bit", rpm:"libssl33-debuginfo-32bit~2.2.1~2.3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtls4-32bit", rpm:"libtls4-32bit~2.2.1~2.3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtls4-debuginfo-32bit", rpm:"libtls4-debuginfo-32bit~2.2.1~2.3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libressl-devel-doc", rpm:"libressl-devel-doc~2.2.1~2.3.1", rls:"openSUSE13.2"))) {
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

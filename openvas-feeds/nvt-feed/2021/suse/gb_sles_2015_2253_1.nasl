# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.2253.1");
  script_cve_id("CVE-2015-3194", "CVE-2015-3195", "CVE-2015-3196");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:09 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-12-07 17:46:25 +0000 (Mon, 07 Dec 2015)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:2253-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:2253-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20152253-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937085");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957812");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957815");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-December/001731.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the SUSE-SU-2015:2253-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2015-3194: The signature verification routines will crash with a
 NULL pointer dereference if presented with an ASN.1 signature using the
 RSA PSS algorithm and absent mask generation function parameter. Since
 these routines are used to verify certificate signature algorithms
 this can be used to crash any certificate verification operation and
 exploited in a DoS attack. Any application which performs certificate
 verification is vulnerable including OpenSSL clients and servers which
 enable client authentication. (bsc#957815)
- CVE-2015-3195: When presented with a malformed X509_ATTRIBUTE structure OpenSSL would leak
 memory. This structure is used by the PKCS#7 and CMS routines so any
 application which reads PKCS#7 or CMS data from untrusted sources is affected.
 SSL/TLS is not affected. (bsc#957812)
- CVE-2015-3196: If PSK identity hints are received by a multi-threaded client then
 the values were wrongly updated in the parent SSL_CTX structure. This could
 result in a race condition potentially leading to a double free of the
 identify hint data. (bsc#957813)

Non security bugs fixed:
- Improve S/390 performance on IBM z196 and z13 (bsc#954256)
- Add support for 'ciphers' providing no encryption (bsc#937085)");

  script_tag(name:"affected", value:"'openssl' package(s) on SUSE Linux Enterprise Server 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1-devel", rpm:"libopenssl1-devel~1.0.1g~0.35.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0", rpm:"libopenssl1_0_0~1.0.1g~0.35.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-32bit", rpm:"libopenssl1_0_0-32bit~1.0.1g~0.35.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-x86", rpm:"libopenssl1_0_0-x86~1.0.1g~0.35.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl1", rpm:"openssl1~1.0.1g~0.35.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl1-doc", rpm:"openssl1-doc~1.0.1g~0.35.1", rls:"SLES11.0"))) {
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

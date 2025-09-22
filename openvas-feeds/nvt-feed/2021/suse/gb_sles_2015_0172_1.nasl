# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0172.1");
  script_cve_id("CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0205", "CVE-2015-0206");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:14 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0172-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0172-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150172-1/");
  script_xref(name:"URL", value:"http://openssl.org/news/secadv_20150108.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'OpenSSL' package(s) announced via the SUSE-SU-2015:0172-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OpenSSL has been updated to fix various security issues.

More information can be found in the OpenSSL advisory:
[link moved to references] .
The following issues have been fixed:
 *
 CVE-2014-3570: Bignum squaring (BN_sqr) may have produced incorrect results on some platforms, including x86_64. (bsc#912296)
 *
 CVE-2014-3571: Fixed crash in dtls1_get_record whilst in the listen state where you get two separate reads performed - one for the header and one for the body of the handshake record. (bsc#912294)
 *
 CVE-2014-3572: Don't accept a handshake using an ephemeral ECDH ciphersuites with the server key exchange message omitted. (bsc#912015)
 *
 CVE-2014-8275: Fixed various certificate fingerprint issues.
(bsc#912018)
 *
 CVE-2015-0204: Only allow ephemeral RSA keys in export ciphersuites.
(bsc#912014)
 *
 CVE-2015-0205: A fix was added to prevent use of DH client certificates without sending certificate verify message. Although the OpenSSL library from SLES 10 is not affected by this problem, a fix has been applied to the sources. (bsc#912293)
 *
 CVE-2015-0206: A memory leak was fixed in dtls1_buffer_record.
(bsc#912292)
Security Issues:
 * CVE-2014-8275
 * CVE-2014-3571
 * CVE-2015-0204
 * CVE-2014-3572
 * CVE-2014-3570
 * CVE-2015-0205");

  script_tag(name:"affected", value:"'OpenSSL' package(s) on SUSE Linux Enterprise Server 10-SP4, SUSE Manager 1.7, SUSE Studio Onsite 1.3.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8a~18.88.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-32bit", rpm:"openssl-32bit~0.9.8a~18.88.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.8a~18.88.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel-32bit", rpm:"openssl-devel-32bit~0.9.8a~18.88.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~0.9.8a~18.88.1", rls:"SLES10.0SP4"))) {
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

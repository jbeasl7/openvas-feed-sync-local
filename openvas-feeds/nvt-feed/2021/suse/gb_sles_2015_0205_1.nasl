# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0205.1");
  script_cve_id("CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0205", "CVE-2015-0206");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0205-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0205-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150205-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the SUSE-SU-2015:0205-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OpenSSL was updated to fix security issues and also provide FIPS compliance.

Security issues fixed: CVE-2014-3570: Bignum squaring (BN_sqr) may have produced incorrect results on some platforms, including x86_64.

CVE-2014-3571: Fixed crash in dtls1_get_record whilst in the listen state where you get two separate reads performed - one for the header and one for the body of the handshake record.

CVE-2014-3572: No longer accept a handshake using an ephemeral ECDH ciphersuites with the server key exchange message omitted.

CVE-2014-8275: Fixed various certificate fingerprint issues.

CVE-2015-0204: Only allow ephemeral RSA keys in export ciphersuites.

CVE-2015-0205: Fix to prevent use of DH client certificates without sending certificate verify message.

CVE-2015-0206: A memory leak could have occurred in dtls1_buffer_record.

Bugfixes:
- Do not advertise curves we don't support (bsc#906878)

FIPS changes:
- Make RSA2 key generation FIPS 186-4 compliant (bsc#901902)

- X9.31 rand method is not allowed in FIPS mode.

- Do not allow dynamic ENGINEs loading in FIPS mode.

- Added a locking hack which prevents hangs in FIPS mode (bsc#895129)

- In non-FIPS RSA key generation, mirror the maximum and minimum limiters
 from FIPS rsa generation to meet Common Criteria and BSI TR requirements
 on minimum and maximum distances between p and q. (bsc#908362)

- Do constant reseeding from /dev/urandom, for every random byte pulled,
 seed with
 one byte from /dev/urandom, also change RAND_poll to pull the full state
 size of the SSLEAY DRBG to fulfil Common Criteria requirements.
 (bsc#908372)

FIPS mode can be enabled by either using the environment variable OPENSSL_FORCE_FIPS_MODE=1 or supplying the 'fips=1' parameter on the kernel boot commandline.");

  script_tag(name:"affected", value:"'openssl' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Software Development Kit 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0", rpm:"libopenssl1_0_0~1.0.1i~17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-32bit", rpm:"libopenssl1_0_0-32bit~1.0.1i~17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-debuginfo", rpm:"libopenssl1_0_0-debuginfo~1.0.1i~17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-debuginfo-32bit", rpm:"libopenssl1_0_0-debuginfo-32bit~1.0.1i~17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-hmac", rpm:"libopenssl1_0_0-hmac~1.0.1i~17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-hmac-32bit", rpm:"libopenssl1_0_0-hmac-32bit~1.0.1i~17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1i~17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~1.0.1i~17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-debugsource", rpm:"openssl-debugsource~1.0.1i~17.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~1.0.1i~17.1", rls:"SLES12.0"))) {
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

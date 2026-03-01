# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20434.1");
  script_cve_id("CVE-2026-22791", "CVE-2026-23893");
  script_tag(name:"creation_date", value:"2026-02-20 04:36:11 +0000 (Fri, 20 Feb 2026)");
  script_version("2026-02-20T05:55:45+0000");
  script_tag(name:"last_modification", value:"2026-02-20 05:55:45 +0000 (Fri, 20 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-03 18:47:15 +0000 (Tue, 03 Feb 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20434-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20434-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620434-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257116");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024341.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openCryptoki' package(s) announced via the SUSE-SU-2026:20434-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2026-22791: supplying malformed compressed EC public key can lead to heap corruption or denial-of-service (bsc#1256673).
 - CVE-2026-23893: Privilege Escalation or Data Exposure via Symlink Following (bsc#1257116).

Other fixes:

 * Soft: Add support for RSA keys up to 16K bits.
 * CCA: Add support for RSA keys up to 8K bits (requires CCA v8.4 or v7.6 or later).
 * p11sak: Add support for generating RSA keys up to 16K bits.
 * Soft/ICA: Add support for SHA512/224 and SHA512/256 key derivation mechanism (CKM_SHA512_224_KEY_DERIVATION and CKM_SHA512_256_KEY_DERIVATION).
 * Soft/ICA/CCA/EP11: Add support for SHA-HMAC key types CKK_SHAxxx_HMAC and key gen mechanisms CKM_SHAxxx_KEY_GEN.
 * p11sak: Add support for SHA-HMAC key types and key generation.
 * p11sak: Add support for key wrap and unwrap commands to export and import private and secret keys by means of key wrapping/unwrapping
 with various key wrapping mechanism.
 * p11kmip: Add support for using an HSM-protected TLS client key via a PKCS#11 provider.
 * p11sak: Add support for exporting non-sensitive private keys to password protected PEM files.
 * Add support for canceling an operation via NULL mechanism pointer at C_XxxInit() call as an alternative to C_SessionCancel() (PKCS#11 v3.0).
 * EP11: Add support for pairing friendly BLS12-381 EC curve for sign/verify using CKM_IBM_ECDSA_OTHER and signature/public key aggregation using CKM_IBM_EC_AGGREGATE.
 * p11sak: Add support for generating BLS12-381 EC keys.
 * EP11: Add support for IBM-specific ML-DSA and ML-KEM key types and mechanisms (requires an EP11 host library v4.2 or later, and
 a CEX8P crypto card with firmware v9.6 or later on IBM z17, and v8.39 or later on IBM z16).
 * CCA: Add support for IBM-specific ML-DSA and ML-KEM key types and mechanisms (requires CCA v8.4 or later).
 * Soft: Add support for IBM-specific ML-DSA and ML-KEM key types and mechanisms (requires OpenSSL 3.5 or later, or the OQS-provider must be configured).
 * p11sak: Add support for IBM-specific ML-DSA and ML-KEM key types.
 * Bug fixes.");

  script_tag(name:"affected", value:"'openCryptoki' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"openCryptoki", rpm:"openCryptoki~3.26.0~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openCryptoki-64bit", rpm:"openCryptoki-64bit~3.26.0~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openCryptoki-devel", rpm:"openCryptoki-devel~3.26.0~160000.1.1", rls:"SLES16.0.0"))) {
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

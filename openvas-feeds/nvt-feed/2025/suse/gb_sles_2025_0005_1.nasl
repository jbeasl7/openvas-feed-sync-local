# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0005.1");
  script_cve_id("CVE-2024-36405", "CVE-2024-37305", "CVE-2024-54137");
  script_tag(name:"creation_date", value:"2025-06-04 14:43:37 +0000 (Wed, 04 Jun 2025)");
  script_version("2025-08-21T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-08-21 05:40:06 +0000 (Thu, 21 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-20 19:07:12 +0000 (Wed, 20 Aug 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0005-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0005-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250005-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234292");
  script_xref(name:"URL", value:"https://csrc.nist.gov/Projects/pqc-dig-sig/round-1-additional-signatures");
  script_xref(name:"URL", value:"https://csrc.nist.gov/pubs/fips/203/final");
  script_xref(name:"URL", value:"https://csrc.nist.gov/pubs/fips/204/final");
  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/html/rfc8391");
  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/html/rfc8554");
  script_xref(name:"URL", value:"https://github.com/formosa-crypto/libjade/releases/tag/release%2F2023.05-2");
  script_xref(name:"URL", value:"https://github.com/open-quantum-safe/liboqs/issues/2001");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-January/020060.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'liboqs, oqs-provider' package(s) announced via the SUSE-SU-2025:0005-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for liboqs, oqs-provider fixes the following issues:

This update supplies the new FIPS standardized ML-KEM, ML-DSA, SHL-DSA algorithms.

This update liboqs to 0.12.0:

 - This release updates the ML-DSA implementation to the [final
 FIPS 204]([link moved to references]) version. This
 release still includes the NIST Round 3 version of Dilithium for
 interoperability purposes, but we plan to remove Dilithium Round 3 in
 a future release.
 - This will be the last release of liboqs to include Kyber (that is,
 the NIST Round 3 version of Kyber, prior to its standardization by NIST
 as ML-KEM in FIPS 203). Applications should switch to ML-KEM (FIPS 203).
 - The addition of ML-DSA FIPS 204 final version to liboqs has
 introduced a new signature API which includes a context string
 parameter. We are planning to remove the old version of the API
 without a context string in the next release to streamline the
 API and bring it in line with NIST specifications. Users who
 have an opinion on this removal are invited to provide input at
 [link moved to references].

 Security issues:

 - CVE-2024-54137: Fixed bug in HQC decapsulation that leads to incorrect
 shared secret value during decapsulation when called with an invalid
 ciphertext. (bsc#1234292)
 - new library major version 7

Updated to 0.11.0:

 * This release updates ML-KEM implementations to their final FIPS 203
 [link moved to references] versions .
 * This release still includes the NIST Round 3 version of Kyber for
 interoperability purposes, but we plan to remove Kyber Round 3 in a
 future release.
 * Additionally, this release adds support for MAYO and CROSS
 digital signature schemes from [NIST Additional Signatures Round 1
 [link moved to references]
 along with stateful hash-based signature schemes XMSS
 [link moved to references] and LMS
 [link moved to references].
 * Finally, this release provides formally verified
 implementations of Kyber-512 and Kyber-768 from libjade
 [link moved to references]
 * LMS and XMSS are disabled by default due to the security risks associated with their use in software.
 See the note on stateful hash-based signatures in CONFIGURE.md
 * Key encapsulation mechanisms:
 - Kyber: Added formally-verified portable C and AVX2 implementations
 of Kyber-512 and Kyber-768 from libjade.
 - ML-KEM: Updated portable C and AVX2 implementations of ML-KEM-512,
 ML-KEM-768, and ML-KEM-1024 to FIP 203 version.
 - Kyber: Patched ARM64 implementations of Kyber-512, Kyber-768, and
 Kyber-1024 to work with AddressSanitizer.
 * Digital signature schemes:
 - LMS/XMSS: Added implementations of stateful hash-based signature
 schemes: XMSS and LMS
 - MAYO: Added portable C and AVX2 implementations of MAYO signature
 scheme from NIST Additional Signatures Round 1.
 - CROSS: Added portable C and AVX2 implementations of CROSS signature
 scheme from NIST Additional Signatures Round 1.
 * Other ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'liboqs, oqs-provider' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"liboqs-devel", rpm:"liboqs-devel~0.12.0~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liboqs7", rpm:"liboqs7~0.12.0~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oqs-provider", rpm:"oqs-provider~0.7.0~150600.3.3.1", rls:"SLES15.0SP6"))) {
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

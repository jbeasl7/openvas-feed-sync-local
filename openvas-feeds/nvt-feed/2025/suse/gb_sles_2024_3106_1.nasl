# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3106.1");
  script_cve_id("CVE-2024-6119");
  script_tag(name:"creation_date", value:"2025-06-04 14:43:37 +0000 (Wed, 04 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-03 10:51:54 +0000 (Tue, 03 Jun 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3106-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3106-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243106-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220690");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220696");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221751");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221753");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229465");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-September/036766.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl-3' package(s) announced via the SUSE-SU-2024:3106-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl-3 fixes the following issues:

- CVE-2024-6119: Fixed denial of service in X.509 name checks (bsc#1229465)

Other fixes:

- FIPS: Deny SHA-1 signature verification in FIPS provider (bsc#1221365).
- FIPS: RSA keygen PCT requirements.
- FIPS: Check that the fips provider is available before setting
 it as the default provider in FIPS mode (bsc#1220523).
- FIPS: Port openssl to use jitterentropy (bsc#1220523).
- FIPS: Block non-Approved Elliptic Curves (bsc#1221786).
- FIPS: Service Level Indicator (bsc#1221365).
- FIPS: Output the FIPS-validation name and module version which uniquely
 identify the FIPS validated module (bsc#1221751).
- FIPS: Add required selftests: (bsc#1221760).
- FIPS: DH: Disable FIPS 186-4 Domain Parameters (bsc#1221821).
- FIPS: Recommendation for Password-Based Key Derivation (bsc#1221827).
- FIPS: Zero initialization required (bsc#1221752).
- FIPS: Reseed DRBG (bsc#1220690, bsc#1220693, bsc#1220696).
- FIPS: NIST SP 800-56Brev2 (bsc#1221824).
- FIPS: Approved Modulus Sizes for RSA Digital Signature for FIPS 186-4 (bsc#1221787).
- FIPS: Port openssl to use jitterentropy (bsc#1220523).
- FIPS: NIST SP 800-56Arev3 (bsc#1221822).
- FIPS: Error state has to be enforced (bsc#1221753).");

  script_tag(name:"affected", value:"'openssl-3' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-3-devel", rpm:"libopenssl-3-devel~3.1.4~150600.5.15.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-3-fips-provider", rpm:"libopenssl-3-fips-provider~3.1.4~150600.5.15.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-3-fips-provider-32bit", rpm:"libopenssl-3-fips-provider-32bit~3.1.4~150600.5.15.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3", rpm:"libopenssl3~3.1.4~150600.5.15.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3-32bit", rpm:"libopenssl3-32bit~3.1.4~150600.5.15.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-3", rpm:"openssl-3~3.1.4~150600.5.15.1", rls:"SLES15.0SP6"))) {
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

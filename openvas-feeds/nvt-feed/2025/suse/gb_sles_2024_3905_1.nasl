# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3905.1");
  script_cve_id("CVE-2023-50782");
  script_tag(name:"creation_date", value:"2025-06-04 14:43:37 +0000 (Wed, 04 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-14 17:52:10 +0000 (Wed, 14 Feb 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3905-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3905-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243905-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224264");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224265");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224266");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224267");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224268");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224270");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224271");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224272");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224273");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228623");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-November/019774.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl-1_1' package(s) announced via the SUSE-SU-2024:3905-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2023-50782: Implicit rejection in PKCS#1 v1.5 (bsc#1220262)

Other fixes:

- FIPS: AES GCM external IV implementation (bsc#1228618)
- FIPS: Mark PBKDF2 and HKDF HMAC input keys with size >= 112 bits as approved in the SLI. (bsc#1228623)
- FIPS: Enforce KDF in FIPS style (bsc#1224270)
- FIPS: Mark HKDF and TLSv1.3 KDF as approved in the SLI (bsc#1228619)
- FIPS: The X9.31 scheme is not approved for RSA signature operations in FIPS 186-5. (bsc#1224269)
- FIPS: Differentiate the PSS length requirements (bsc#1224275)
- FIPS: Mark sigGen and sigVer primitives as non-approved (bsc#1224272)
- FIPS: Disable PKCSv1.5 and shake in FIPS mode (bsc#1224271)
- FIPS: Mark SHA1 as non-approved in the SLI (bsc#1224266)
- FIPS: DH FIPS selftest and safe prime group (bsc#1224264)
- FIPS: Remove not needed FIPS DRBG files (bsc#1224268)
- FIPS: Add Pair-wise Consistency Test when generating DH key (bsc#1224265)
- FIPS: Disallow non-approved KDF types (bsc#1224267)
- FIPS: Disallow RSA sigVer with 1024 and ECDSA sigVer/keyVer P-192 (bsc#1224273)
- FIPS: DRBG component chaining (bsc#1224258)
- FIPS: Align CRNGT_BUFSIZ with Jitter RNG output size (bsc#1224260)");

  script_tag(name:"affected", value:"'openssl-1_1' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1", rpm:"libopenssl1_1~1.1.1w~150600.5.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-32bit", rpm:"libopenssl1_1-32bit~1.1.1w~150600.5.9.1", rls:"SLES15.0SP6"))) {
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

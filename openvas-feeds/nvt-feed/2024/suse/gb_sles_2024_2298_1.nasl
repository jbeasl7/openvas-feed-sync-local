# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2298.1");
  script_cve_id("CVE-2024-0914");
  script_tag(name:"creation_date", value:"2024-07-05 04:25:11 +0000 (Fri, 05 Jul 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 01:01:38 +0000 (Fri, 09 Feb 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2298-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2298-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242298-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220266");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-July/018865.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openCryptoki' package(s) announced via the SUSE-SU-2024:2298-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openCryptoki fixes the following issues:

openCryptoki was updated to version to 3.17.0 (bsc#1220266, bsc#1219217)

+ openCryptoki 3.17

 - tools: added function to list keys to p11sak
 - common: added support for OpenSSL 3.0
 - common: added support for event notifications
 - ICA: added SW fallbacks

+ openCryptoki 3.16

 - EP11: protected-key option
 - EP11: support attribute-bound keys
 - CCA: import and export of secure key objects
 - Bug fixes

+ openCryptoki 3.15.1

 - Bug fixes

+ openCryptoki 3.15

 - common: conform to PKCS 11 3.0 Baseline Provider profile
 - Introduce new vendor defined interface named 'Vendor IBM'
 - Support C_IBM_ReencryptSingle via 'Vendor IBM' interface
 - CCA: support key wrapping
 - SOFT: support ECC
 - p11sak tool: add remove-key command
 - Bug fixes

+ openCryptoki 3.14

 - EP11: Dilitium support stage 2
 - Common: Rework on process and thread locking
 - Common: Rework on btree and object locking
 - ICSF: minor fixes
 - TPM, ICA, ICSF: support multiple token instances
 - new tool p11sak

+ openCryptoki 3.13.0

 - EP11: Dilithium support
 - EP11: EdDSA support
 - EP11: support RSA-OAEP with non-SHA1 hash and MGF

+ openCryptoki 3.12.1

 - Fix pkcsep11_migrate tool

+ openCryptoki 3.12.0

 - Update token pin and data store encryption for soft,ica,cca and ep11
 - EP11: Allow importing of compressed EC public keys
 - EP11: Add support for the CMAC mechanisms
 - EP11: Add support for the IBM-SHA3 mechanisms
 - SOFT: Add AES-CMAC and 3DES-CMAC support to the soft token
 - ICA: Add AES-CMAC and 3DES-CMAC support to the ICA token
 - EP11: Add config option USE_PRANDOM
 - CCA: Use Random Number Generate Long for token_specific_rng()
 - Common rng function: Prefer /dev/prandom over /dev/urandom
 - ICA: add SHA*_RSA_PKCS_PSS mechanisms
 - Bug fixes");

  script_tag(name:"affected", value:"'openCryptoki' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"openCryptoki", rpm:"openCryptoki~3.17.0~5.9.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openCryptoki-32bit", rpm:"openCryptoki-32bit~3.17.0~5.9.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openCryptoki-64bit", rpm:"openCryptoki-64bit~3.17.0~5.9.2", rls:"SLES12.0SP5"))) {
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

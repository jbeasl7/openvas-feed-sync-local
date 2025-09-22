# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2600.1");
  script_cve_id("CVE-2023-5388");
  script_tag(name:"creation_date", value:"2024-07-24 04:23:51 +0000 (Wed, 24 Jul 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2600-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2600-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242600-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214980");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222807");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222826");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222828");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222833");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224113");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224116");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224118");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-July/019020.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-nss' package(s) announced via the SUSE-SU-2024:2600-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mozilla-nss fixes the following issues:

- FIPS: Added more safe memset (bsc#1222811).
- FIPS: Adjusted AES GCM restrictions (bsc#1222830).
- FIPS: Adjusted approved ciphers (bsc#1222813, bsc#1222814, bsc#1222821,
 bsc#1222822, bsc#1224118, bsc#1222807, bsc#1222828, bsc#1222834,
 bsc#1222804, bsc#1222826, bsc#1222833, bsc#1224113, bsc#1224115,
 bsc#1224116).

Update to NSS 3.101.1:

* GLOBALTRUST 2020: Set Distrust After for TLS and S/MIME.

update to NSS 3.101:

* add diagnostic assertions for SFTKObject refcount.
* freeing the slot in DeleteCertAndKey if authentication failed
* fix formatting issues.
* Add Firmaprofesional CA Root-A Web to NSS.
* remove invalid acvp fuzz test vectors.
* pad short P-384 and P-521 signatures gtests.
* remove unused FreeBL ECC code.
* pad short P-384 and P-521 signatures.
* be less strict about ECDSA private key length.
* Integrate HACL* P-521.
* Integrate HACL* P-384.
* memory leak in create_objects_from_handles.
* ensure all input is consumed in a few places in mozilla::pkix
* SMIME/CMS and PKCS #12 do not integrate with modern NSS policy
* clean up escape handling
* Use lib::pkix as default validator instead of the old-one
* Need to add high level support for PQ signing.
* Certificate Compression: changing the allocation/freeing of buffer + Improving the documentation
* SMIME/CMS and PKCS #12 do not integrate with modern NSS policy
* Allow for non-full length ecdsa signature when using softoken
* Modification of .taskcluster.yml due to mozlint indent defects
* Implement support for PBMAC1 in PKCS#12
* disable VLA warnings for fuzz builds.
* remove redundant AllocItem implementation.
* add PK11_ReadDistrustAfterAttribute.
* - Clang-formatting of SEC_GetMgfTypeByOidTag update
* Set SEC_ERROR_LIBRARY_FAILURE on self-test failure
* sftk_getParameters(): Fix fallback to default variable after error with configfile.
* Switch to the mozillareleases/image_builder image

- switch from ec_field_GFp to ec_field_plain

Update to NSS 3.100:

* merge pk11_kyberSlotList into pk11_ecSlotList for faster Xyber operations.
* remove ckcapi.
* avoid a potential PK11GenericObject memory leak.
* Remove incomplete ESDH code.
* Decrypt RSA OAEP encrypted messages.
* Fix certutil CRLDP URI code.
* Don't set CKA_DERIVE for CKK_EC_EDWARDS private keys.
* Add ability to encrypt and decrypt CMS messages using ECDH.
* Correct Templates for key agreement in smime/cmsasn.c.
* Moving the decodedCert allocation to NSS.
* Allow developers to speed up repeated local execution of NSS tests that depend on certificates.

Update to NSS 3.99:

* Removing check for message len in ed25519 (bmo#1325335)
* add ed25519 to SECU_ecName2params. (bmo#1884276)
* add EdDSA wycheproof tests. (bmo#1325335)
* nss/lib layer code for EDDSA. (bmo#1325335)
* Adding EdDSA implementation. (bmo#1325335)
* Exporting Certificate Compression types (bmo#1881027)
* Updating ACVP docker ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'mozilla-nss' package(s) on SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.101.1~150000.3.117.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.101.1~150000.3.117.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.101.1~150000.3.117.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.101.1~150000.3.117.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.101.1~150000.3.117.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.101.1~150000.3.117.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.101.1~150000.3.117.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.101.1~150000.3.117.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.101.1~150000.3.117.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit", rpm:"mozilla-nss-sysinit~3.101.1~150000.3.117.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.101.1~150000.3.117.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.101.1~150000.3.117.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.101.1~150000.3.117.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.101.1~150000.3.117.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.101.1~150000.3.117.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.101.1~150000.3.117.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.101.1~150000.3.117.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.101.1~150000.3.117.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.101.1~150000.3.117.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.101.1~150000.3.117.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit", rpm:"mozilla-nss-sysinit~3.101.1~150000.3.117.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-32bit", rpm:"mozilla-nss-sysinit-32bit~3.101.1~150000.3.117.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.101.1~150000.3.117.1", rls:"SLES15.0SP3"))) {
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

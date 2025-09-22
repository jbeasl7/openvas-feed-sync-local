# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.14418.1");
  script_cve_id("CVE-2019-11727", "CVE-2019-11745", "CVE-2019-17006", "CVE-2020-12399", "CVE-2020-12402");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:00 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-26 20:03:18 +0000 (Mon, 26 Oct 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:14418-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:14418-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-202014418-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159819");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168669");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173032");
  script_xref(name:"URL", value:"https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.53_release_notes");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-July/007079.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-nspr, mozilla-nss' package(s) announced via the SUSE-SU-2020:14418-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mozilla-nspr, mozilla-nss fixes the following issues:

mozilla-nss was updated to version 3.53.1

- CVE-2019-11745: Out-of-bounds write when passing an output buffer smaller than the block size to NSC_EncryptUpdate
- CVE-2020-12402: Fixed a potential side channel attack during RSA key generation (bsc#1173032).
- CVE-2020-12399: Fixed a timing attack on DSA signature generation (bsc#1171978).
- CVE-2019-17006: Added length checks for cryptographic primitives (bsc#1159819).
- CVE-2019-11727: A vulnerability exists where it possible to force Network Security Services (NSS) to sign CertificateVerify with PKCS#1 v1.5 signatures when those are the only ones advertised by server in CertificateRequest in TLS 1.3. PKCS#1 v1.5 signatures should not be used for TLS 1.3 messages.
- Fixed various FIPS issues in libfreebl3 which were causing segfaults in the test suite of chrony (bsc#1168669).
- Fixed an issue where Firefox tab was crashing (bsc#1170908).

Release notes: [link moved to references]

mozilla-nspr was updated to version 4.25.");

  script_tag(name:"affected", value:"'mozilla-nspr, mozilla-nss' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.53.1~38.23.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.53.1~38.23.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.53.1~38.23.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.53.1~38.23.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.25~29.12.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.25~29.12.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.25~29.12.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.53.1~38.23.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.53.1~38.23.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.53.1~38.23.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.53.1~38.23.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.53.1~38.23.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.53.1~38.23.1", rls:"SLES11.0SP4"))) {
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

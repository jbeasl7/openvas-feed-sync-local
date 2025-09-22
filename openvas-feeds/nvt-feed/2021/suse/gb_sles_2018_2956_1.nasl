# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2956.1");
  script_cve_id("CVE-2018-0732");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:36 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-10 16:42:33 +0000 (Fri, 10 Aug 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2956-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2956-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182956-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl-1_1' package(s) announced via the SUSE-SU-2018:2956-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl-1_1 to 1.1.0i fixes the following issues:

These security issues were fixed:
CVE-2018-0732: During key agreement in a TLS handshake using a DH(E)
 based ciphersuite a malicious server could have sent a very large prime
 value to the client. This caused the client to spend an unreasonably
 long period of time generating a key for this prime resulting in a hang
 until the client has finished. This could be exploited in a Denial Of
 Service attack (bsc#1097158)

Make problematic ECDSA sign addition length-invariant

Add blinding to ECDSA and DSA signatures to protect against side channel
 attacks

These non-security issues were fixed:
When unlocking a pass phrase protected PEM file or PKCS#8 container, we
 now allow empty (zero character) pass phrases.

Certificate time validation (X509_cmp_time) enforces stricter compliance
 with RFC 5280. Fractional seconds and timezone offsets are no longer
 allowed.

Fixed a text canonicalisation bug in CMS

Add openssl(cli) Provide so the packages that require the openssl binary
 can require this instead of the new openssl meta package (bsc#1101470)");

  script_tag(name:"affected", value:"'openssl-1_1' package(s) on SUSE Linux Enterprise Module for Basesystem 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_1-devel", rpm:"libopenssl-1_1-devel~1.1.0i~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~1.1.0i~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1", rpm:"libopenssl1_1~1.1.0i~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-32bit", rpm:"libopenssl1_1-32bit~1.1.0i~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-32bit-debuginfo", rpm:"libopenssl1_1-32bit-debuginfo~1.1.0i~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-debuginfo", rpm:"libopenssl1_1-debuginfo~1.1.0i~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-hmac", rpm:"libopenssl1_1-hmac~1.1.0i~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-hmac-32bit", rpm:"libopenssl1_1-hmac-32bit~1.1.0i~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.1.0i~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1", rpm:"openssl-1_1~1.1.0i~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1-debuginfo", rpm:"openssl-1_1-debuginfo~1.1.0i~4.9.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1-debugsource", rpm:"openssl-1_1-debugsource~1.1.0i~4.9.2", rls:"SLES15.0"))) {
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

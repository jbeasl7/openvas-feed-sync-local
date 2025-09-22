# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0948.1");
  script_cve_id("CVE-2020-11501");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-22 18:01:09 +0000 (Wed, 22 Apr 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0948-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0948-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200948-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155327");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168345");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-April/006686.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gmp, gnutls, libnettle' package(s) announced via the SUSE-SU-2020:0948-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gmp, gnutls, libnettle fixes the following issues:

Security issue fixed:

- CVE-2020-11501: Fixed zero random value in DTLS client hello (bsc#1168345)

FIPS related bugfixes:

- FIPS: Install checksums for binary integrity verification which are
 required when running in FIPS mode (bsc#1152692, jsc#SLE-9518)
- FIPS: Fixed a cfb8 decryption issue, no longer truncate output IV if
 input is shorter than block size. (bsc#1166881)
- FIPS: Added Diffie Hellman public key verification test. (bsc#1155327)");

  script_tag(name:"affected", value:"'gmp, gnutls, libnettle' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"gmp-debugsource", rpm:"gmp-debugsource~6.1.2~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gmp-devel", rpm:"gmp-devel~6.1.2~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~3.6.7~6.14.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-debuginfo", rpm:"gnutls-debuginfo~3.6.7~6.14.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-debugsource", rpm:"gnutls-debugsource~3.6.7~6.14.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmp10-32bit", rpm:"libgmp10-32bit~6.1.2~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmp10-32bit-debuginfo", rpm:"libgmp10-32bit-debuginfo~6.1.2~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmp10", rpm:"libgmp10~6.1.2~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmp10-debuginfo", rpm:"libgmp10-debuginfo~6.1.2~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmpxx4", rpm:"libgmpxx4~6.1.2~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmpxx4-debuginfo", rpm:"libgmpxx4-debuginfo~6.1.2~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls-devel", rpm:"libgnutls-devel~3.6.7~6.14.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30", rpm:"libgnutls30~3.6.7~6.14.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-32bit", rpm:"libgnutls30-32bit~3.6.7~6.14.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-32bit-debuginfo", rpm:"libgnutls30-32bit-debuginfo~3.6.7~6.14.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-debuginfo", rpm:"libgnutls30-debuginfo~3.6.7~6.14.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-hmac", rpm:"libgnutls30-hmac~3.6.7~6.14.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-hmac-32bit", rpm:"libgnutls30-hmac-32bit~3.6.7~6.14.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutlsxx-devel", rpm:"libgnutlsxx-devel~3.6.7~6.14.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutlsxx28", rpm:"libgnutlsxx28~3.6.7~6.14.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutlsxx28-debuginfo", rpm:"libgnutlsxx28-debuginfo~3.6.7~6.14.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhogweed4", rpm:"libhogweed4~3.4.1~4.12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhogweed4-32bit", rpm:"libhogweed4-32bit~3.4.1~4.12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhogweed4-32bit-debuginfo", rpm:"libhogweed4-32bit-debuginfo~3.4.1~4.12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhogweed4-debuginfo", rpm:"libhogweed4-debuginfo~3.4.1~4.12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnettle-debugsource", rpm:"libnettle-debugsource~3.4.1~4.12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnettle-devel", rpm:"libnettle-devel~3.4.1~4.12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnettle6", rpm:"libnettle6~3.4.1~4.12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnettle6-32bit", rpm:"libnettle6-32bit~3.4.1~4.12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnettle6-32bit-debuginfo", rpm:"libnettle6-32bit-debuginfo~3.4.1~4.12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnettle6-debuginfo", rpm:"libnettle6-debuginfo~3.4.1~4.12.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gmp-devel-32bit", rpm:"gmp-devel-32bit~6.1.2~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmpxx4-32bit", rpm:"libgmpxx4-32bit~6.1.2~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmpxx4-32bit-debuginfo", rpm:"libgmpxx4-32bit-debuginfo~6.1.2~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"gmp-devel-32bit", rpm:"gmp-devel-32bit~6.1.2~4.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gmp-devel", rpm:"gmp-devel~6.1.2~4.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~3.6.7~6.14.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmp10-32bit", rpm:"libgmp10-32bit~6.1.2~4.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmp10", rpm:"libgmp10~6.1.2~4.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmpxx4-32bit", rpm:"libgmpxx4-32bit~6.1.2~4.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmpxx4", rpm:"libgmpxx4~6.1.2~4.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls-devel", rpm:"libgnutls-devel~3.6.7~6.14.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30", rpm:"libgnutls30~3.6.7~6.14.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-32bit", rpm:"libgnutls30-32bit~3.6.7~6.14.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-hmac", rpm:"libgnutls30-hmac~3.6.7~6.14.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-hmac-32bit", rpm:"libgnutls30-hmac-32bit~3.6.7~6.14.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutlsxx-devel", rpm:"libgnutlsxx-devel~3.6.7~6.14.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutlsxx28", rpm:"libgnutlsxx28~3.6.7~6.14.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhogweed4", rpm:"libhogweed4~3.4.1~4.12.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhogweed4-32bit", rpm:"libhogweed4-32bit~3.4.1~4.12.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnettle-devel", rpm:"libnettle-devel~3.4.1~4.12.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnettle6", rpm:"libnettle6~3.4.1~4.12.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnettle6-32bit", rpm:"libnettle6-32bit~3.4.1~4.12.1", rls:"SLES15.0"))) {
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

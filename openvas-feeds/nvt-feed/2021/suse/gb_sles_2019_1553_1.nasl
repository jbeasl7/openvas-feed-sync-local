# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1553.1");
  script_cve_id("CVE-2016-8610", "CVE-2018-0732", "CVE-2018-0734", "CVE-2018-0737", "CVE-2018-5407", "CVE-2019-1559");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-10 16:42:33 +0000 (Fri, 10 Aug 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1553-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1553-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191553-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098592");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101470");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113534");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117951");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131291");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-June/005586.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the SUSE-SU-2019:1553-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl fixes the following issues:

- CVE-2018-0732: Reject excessively large primes in DH key generation (bsc#1097158)
- CVE-2018-0734: Timing vulnerability in DSA signature generation (bsc#1113652)
- CVE-2018-0737: Cache timing vulnerability in RSA Key Generation (bsc#1089039)
- CVE-2018-5407: Elliptic curve scalar multiplication timing attack defenses (fixes 'PortSmash') (bsc#1113534)
- CVE-2019-1559: Fix 0-byte record padding oracle via SSL_shutdown (bsc#1127080)
- Fix One&Done side-channel attack on RSA (bsc#1104789)
- Reject invalid EC point coordinates (bsc#1131291)
- The 9 Lives of Bleichenbacher's CAT: Cache ATtacks on TLS Implementations (bsc#1117951)
- Add missing error string to CVE-2016-8610 fix (bsc#1110018#c9)
- blinding enhancements for ECDSA and DSA (bsc#1097624, bsc#1098592)

Non security fixes:

- correct the error detection in the fips patch (bsc#1106197)
- Add openssl(cli) Provide so the packages that require the openssl
 binary can require this instead of the new openssl meta package
 (bsc#1101470)");

  script_tag(name:"affected", value:"'openssl' package(s) on SUSE Linux Enterprise Server 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0", rpm:"libopenssl1_0_0~1.0.1i~27.34.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-32bit", rpm:"libopenssl1_0_0-32bit~1.0.1i~27.34.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-hmac", rpm:"libopenssl1_0_0-hmac~1.0.1i~27.34.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-hmac-32bit", rpm:"libopenssl1_0_0-hmac-32bit~1.0.1i~27.34.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1i~27.34.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~1.0.1i~27.34.1", rls:"SLES12.0"))) {
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

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0112.1");
  script_cve_id("CVE-2016-2108", "CVE-2016-7056", "CVE-2016-8610", "CVE-2017-3731", "CVE-2017-3735");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-06 12:32:16 +0000 (Fri, 06 May 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0112-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0112-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180112-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1001502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1001912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004499");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019334");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022085");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022271");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/990592");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-January/003599.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the SUSE-SU-2018:0112-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl fixes the following issues:

Security issues fixed:

- CVE-2016-7056: ECSDA P-256 timing attack key recovery (bsc#1019334)
- CVE-2017-3731: Truncated packet could crash via OOB read (bsc#1022085)
- CVE-2016-8610: remote denial of service in SSL alert handling (bsc#1005878)
- CVE-2017-3735: Malformed X.509 IPAdressFamily could cause OOB read (bsc#1056058)

Bug fixes:

- support alternate root ca chains (bsc#1032261)
- X509_get_default_cert_file() returns an incorrect path (bsc#1022271)
- Segmentation fault in 'openssl speed' when engine library file cannot be found (bsc#1000677)
- adjust DEFAULT_SUSE to meet 1.0.2 and current state (bsc#1027908)
- Missing important ciphers in openssl 1.0.1i-47.1 on SLES12 SP1 (bsc#990592)
- out of bounds read+crash in DES_fcrypt (bsc#1065363)
- tracker bug for January 26th 2017 release (bsc#1021641)
- patch for CVE-2016-2108 fails negative zero exploit (bsc#1001502)
- Birthday attacks on 64-bit block ciphers aka triple-des (SWEET32) (bsc#1001912)
- Include additional patch for CVE-2016-2108 (bsc#1004499)
- openssl DEFAULT_SUSE cipher list is missing ECDHE-ECDSA ciphers (bsc#1055825)");

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

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0", rpm:"libopenssl1_0_0~1.0.1i~27.28.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-32bit", rpm:"libopenssl1_0_0-32bit~1.0.1i~27.28.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-hmac", rpm:"libopenssl1_0_0-hmac~1.0.1i~27.28.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-hmac-32bit", rpm:"libopenssl1_0_0-hmac-32bit~1.0.1i~27.28.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1i~27.28.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~1.0.1i~27.28.1", rls:"SLES12.0"))) {
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

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2714.1");
  script_cve_id("CVE-2016-7167", "CVE-2016-8615", "CVE-2016-8616", "CVE-2016-8617", "CVE-2016-8618", "CVE-2016-8619", "CVE-2016-8620", "CVE-2016-8621", "CVE-2016-8622", "CVE-2016-8623", "CVE-2016-8624");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:03 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-16 12:18:25 +0000 (Tue, 16 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2714-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2714-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162714-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005633");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005646");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998760");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-November/002391.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the SUSE-SU-2016:2714-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for curl fixes the following security issues:

- CVE-2016-8624: invalid URL parsing with '#' (bsc#1005646)
- CVE-2016-8623: Use-after-free via shared cookies (bsc#1005645)
- CVE-2016-8621: curl_getdate read out of bounds (bsc#1005642)
- CVE-2016-8619: double-free in krb5 code (bsc#1005638)
- CVE-2016-8618: double-free in curl_maprintf (bsc#1005637)
- CVE-2016-8617: OOB write via unchecked multiplication (bsc#1005635)
- CVE-2016-8616: case insensitive password comparison (bsc#1005634)
- CVE-2016-8615: cookie injection for other servers (bsc#1005633)
- CVE-2016-7167: escape and unescape integer overflows (bsc#998760)");

  script_tag(name:"affected", value:"'curl' package(s) on SUSE Linux Enterprise Server 11, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"curl-openssl1", rpm:"curl-openssl1~7.19.7~1.64.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-openssl1-32bit", rpm:"libcurl4-openssl1-32bit~7.19.7~1.64.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-openssl1", rpm:"libcurl4-openssl1~7.19.7~1.64.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-openssl1-x86", rpm:"libcurl4-openssl1-x86~7.19.7~1.64.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.19.7~1.64.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-32bit", rpm:"libcurl4-32bit~7.19.7~1.64.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4", rpm:"libcurl4~7.19.7~1.64.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-x86", rpm:"libcurl4-x86~7.19.7~1.64.1", rls:"SLES11.0SP4"))) {
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

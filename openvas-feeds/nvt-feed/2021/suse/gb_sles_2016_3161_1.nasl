# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.3161.1");
  script_cve_id("CVE-2014-8964", "CVE-2015-2325", "CVE-2015-2327", "CVE-2015-2328", "CVE-2015-3210", "CVE-2015-3217", "CVE-2015-5073", "CVE-2015-8380", "CVE-2015-8381", "CVE-2015-8382", "CVE-2015-8383", "CVE-2015-8384", "CVE-2015-8385", "CVE-2015-8386", "CVE-2015-8387", "CVE-2015-8388", "CVE-2015-8389", "CVE-2015-8390", "CVE-2015-8391", "CVE-2015-8392", "CVE-2015-8393", "CVE-2015-8394", "CVE-2015-8395", "CVE-2016-1283", "CVE-2016-3191");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-21 18:10:52 +0000 (Mon, 21 Mar 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:3161-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:3161-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20163161-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/906574");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933288");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942865");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957566");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971741");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/972127");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-December/002488.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pcre' package(s) announced via the SUSE-SU-2016:3161-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pcre to version 8.39 (bsc#972127) fixes several issues.

If you use pcre extensively please be aware that this is an update to a new version. Please make sure that your software works with the updated version.

This version fixes a number of vulnerabilities that affect pcre and applications using the libary when accepting untrusted input as regular expressions or as part thereof. Remote attackers could have caused the application to crash, disclose information or potentially execute arbitrary code. These security issues were fixed:

- CVE-2014-8964: Heap-based buffer overflow in PCRE allowed remote attackers to cause a denial of service (crash) or have other unspecified impact via a crafted regular expression, related to an assertion that allows zero repeats (bsc#906574).
- CVE-2015-2325: Heap buffer overflow in compile_branch() (bsc#924960).
- CVE-2015-3210: Heap buffer overflow in pcre_compile2() / compile_regex() (bsc#933288)
- CVE-2015-3217: PCRE Library Call Stack Overflow Vulnerability in match() (bsc#933878).
- CVE-2015-5073: Library Heap Overflow Vulnerability in find_fixedlength() (bsc#936227).
- bsc#942865: heap overflow in compile_regex()
- CVE-2015-8380: The pcre_exec function in pcre_exec.c mishandled a // pattern with a \01 string, which allowed remote attackers to cause a denial of service (heap-based buffer overflow) or possibly have unspecified other impact via a crafted regular expression, as demonstrated by a JavaScript RegExp object encountered by Konqueror (bsc#957566).
- CVE-2015-2327: PCRE mishandled certain patterns with internal recursive back references, which allowed remote attackers to cause a denial of service (segmentation fault) or possibly have unspecified other impact via a crafted regular expression, as demonstrated by a JavaScript RegExp object encountered by Konqueror (bsc#957567).
- bsc#957598: Various security issues
- CVE-2015-8381: Heap Overflow in compile_regex() (bsc#957598).
- CVE-2015-8382: Regular Expression Uninitialized Pointer Information Disclosure Vulnerability (ZDI-CAN-2547)(bsc#957598).
- CVE-2015-8383: Buffer overflow caused by repeated conditional group(bsc#957598).
- CVE-2015-8384: Buffer overflow caused by recursive back reference by name within certain group(bsc#957598).
- CVE-2015-8385: Buffer overflow caused by forward reference by name to certain group(bsc#957598).
- CVE-2015-8386: Buffer overflow caused by lookbehind assertion(bsc#957598).
- CVE-2015-8387: Integer overflow in subroutine calls(bsc#957598).
- CVE-2015-8388: Buffer overflow caused by certain patterns with an unmatched closing parenthesis(bsc#957598).
- CVE-2015-8389: Infinite recursion in JIT compiler when processing certain patterns(bsc#957598).
- CVE-2015-8390: Reading from uninitialized memory when processing certain patterns(bsc#957598).
- CVE-2015-8391: Some pathological patterns causes pcre_compile() to run for a very long ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'pcre' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpcre1-32bit", rpm:"libpcre1-32bit~8.39~7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1", rpm:"libpcre1~8.39~7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16-0", rpm:"libpcre16-0~8.39~7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libpcre1-32bit", rpm:"libpcre1-32bit~8.39~7.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1", rpm:"libpcre1~8.39~7.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16-0", rpm:"libpcre16-0~8.39~7.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libpcre1-32bit", rpm:"libpcre1-32bit~8.39~7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1", rpm:"libpcre1~8.39~7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16-0", rpm:"libpcre16-0~8.39~7.1", rls:"SLES12.0SP2"))) {
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

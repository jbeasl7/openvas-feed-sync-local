# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1570.1");
  script_cve_id("CVE-2015-9096", "CVE-2016-2339", "CVE-2016-7798", "CVE-2017-0898", "CVE-2017-0899", "CVE-2017-0900", "CVE-2017-0901", "CVE-2017-0902", "CVE-2017-0903", "CVE-2017-10784", "CVE-2017-14033", "CVE-2017-14064", "CVE-2017-17405", "CVE-2017-17742", "CVE-2017-17790", "CVE-2017-9228", "CVE-2017-9229", "CVE-2018-1000073", "CVE-2018-1000074", "CVE-2018-1000075", "CVE-2018-1000076", "CVE-2018-1000077", "CVE-2018-1000078", "CVE-2018-1000079", "CVE-2018-16395", "CVE-2018-16396", "CVE-2018-6914", "CVE-2018-8777", "CVE-2018-8778", "CVE-2018-8779", "CVE-2018-8780", "CVE-2019-15845", "CVE-2019-16201", "CVE-2019-16254", "CVE-2019-16255", "CVE-2019-8320", "CVE-2019-8321", "CVE-2019-8322", "CVE-2019-8323", "CVE-2019-8324", "CVE-2019-8325", "CVE-2020-10663");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-17 18:30:45 +0000 (Mon, 17 Dec 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1570-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1570-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201570-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048072");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055265");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058754");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058755");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1069607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1069632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112530");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112532");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130622");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172275");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-June/006905.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby2.1' package(s) announced via the SUSE-SU-2020:1570-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ruby2.1 fixes the following issues:

Security issues fixed:

- CVE-2015-9096: Fixed an SMTP command injection via CRLFsequences in a RCPT TO or MAIL FROM command (bsc#1043983).
- CVE-2016-7798: Fixed an IV Reuse in GCM Mode (bsc#1055265).
- CVE-2017-0898: Fixed a buffer underrun vulnerability in Kernel.sprintf (bsc#1058755).
- CVE-2017-0899: Fixed an issue with malicious gem specifications, insufficient sanitation when printing gem specifications could have included terminal characters (bsc#1056286).
- CVE-2017-0900: Fixed an issue with malicious gem specifications, the query command could have led to a denial of service attack against clients (bsc#1056286).
- CVE-2017-0901: Fixed an issue with malicious gem specifications, potentially overwriting arbitrary files on the client system (bsc#1056286).
- CVE-2017-0902: Fixed an issue with malicious gem specifications, that could have enabled MITM attacks against clients (bsc#1056286).
- CVE-2017-0903: Fixed an unsafe object deserialization vulnerability (bsc#1062452).
- CVE-2017-9228: Fixed a heap out-of-bounds write in bitset_set_range() during regex compilation (bsc#1069607).
- CVE-2017-9229: Fixed an invalid pointer dereference in left_adjust_char_head() in oniguruma (bsc#1069632).
- CVE-2017-10784: Fixed an escape sequence injection vulnerability in the Basic authentication of WEBrick (bsc#1058754).
- CVE-2017-14033: Fixed a buffer underrun vulnerability in OpenSSL ASN1 decode (bsc#1058757).
- CVE-2017-14064: Fixed an arbitrary memory exposure during a JSON.generate call (bsc#1056782).
- CVE-2017-17405: Fixed a command injection vulnerability in Net::FTP (bsc#1073002).
- CVE-2017-17742: Fixed an HTTP response splitting issue in WEBrick (bsc#1087434).
- CVE-2017-17790: Fixed a command injection in lib/resolv.rb:lazy_initialize() (bsc#1078782).
- CVE-2018-6914: Fixed an unintentional file and directory creation with directory traversal in tempfile and tmpdir (bsc#1087441).
- CVE-2018-8777: Fixed a potential DoS caused by large requests in WEBrick (bsc#1087436).
- CVE-2018-8778: Fixed a buffer under-read in String#unpack (bsc#1087433).
- CVE-2018-8779: Fixed an unintentional socket creation by poisoned NUL byte in UNIXServer and UNIXSocket (bsc#1087440).
- CVE-2018-8780: Fixed an unintentional directory traversal by poisoned NUL byte in Dir (bsc#1087437).
- CVE-2018-16395: Fixed an issue with OpenSSL::X509::Name equality checking (bsc#1112530).
- CVE-2018-16396: Fixed an issue with tainted string handling, where the flag was not propagated in Array#pack and String#unpack with some directives (bsc#1112532).
- CVE-2018-1000073: Fixed a path traversal issue (bsc#1082007).
- CVE-2018-1000074: Fixed an unsafe object deserialization vulnerability in gem owner, allowing arbitrary code execution with specially crafted YAML (bsc#1082008).
- CVE-2018-1000075: Fixed an infinite loop vulnerability due to negative size ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ruby2.1' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libruby2_1-2_1", rpm:"libruby2_1-2_1~2.1.9~19.3.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1", rpm:"ruby2.1~2.1.9~19.3.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-stdlib", rpm:"ruby2.1-stdlib~2.1.9~19.3.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yast2-ruby-bindings", rpm:"yast2-ruby-bindings~3.1.53~9.8.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libruby2_1-2_1", rpm:"libruby2_1-2_1~2.1.9~19.3.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1", rpm:"ruby2.1~2.1.9~19.3.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-stdlib", rpm:"ruby2.1-stdlib~2.1.9~19.3.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libruby2_1-2_1", rpm:"libruby2_1-2_1~2.1.9~19.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1", rpm:"ruby2.1~2.1.9~19.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-stdlib", rpm:"ruby2.1-stdlib~2.1.9~19.3.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libruby2_1-2_1", rpm:"libruby2_1-2_1~2.1.9~19.3.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1", rpm:"ruby2.1~2.1.9~19.3.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-stdlib", rpm:"ruby2.1-stdlib~2.1.9~19.3.2", rls:"SLES12.0SP5"))) {
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

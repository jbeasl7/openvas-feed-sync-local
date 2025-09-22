# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2872.1");
  script_cve_id("CVE-2016-2830", "CVE-2016-5289", "CVE-2016-5292", "CVE-2016-9063", "CVE-2016-9067", "CVE-2016-9068", "CVE-2016-9069", "CVE-2016-9071", "CVE-2016-9073", "CVE-2016-9075", "CVE-2016-9076", "CVE-2016-9077", "CVE-2017-7789", "CVE-2018-5150", "CVE-2018-5151", "CVE-2018-5152", "CVE-2018-5153", "CVE-2018-5154", "CVE-2018-5155", "CVE-2018-5157", "CVE-2018-5158", "CVE-2018-5159", "CVE-2018-5160", "CVE-2018-5163", "CVE-2018-5164", "CVE-2018-5165", "CVE-2018-5166", "CVE-2018-5167", "CVE-2018-5168", "CVE-2018-5169", "CVE-2018-5172", "CVE-2018-5173", "CVE-2018-5174", "CVE-2018-5175", "CVE-2018-5176", "CVE-2018-5177", "CVE-2018-5178", "CVE-2018-5179", "CVE-2018-5180", "CVE-2018-5181", "CVE-2018-5182", "CVE-2018-5183", "CVE-2019-11757", "CVE-2019-11758", "CVE-2019-11759", "CVE-2019-11760", "CVE-2019-11761", "CVE-2019-11762", "CVE-2019-11763", "CVE-2019-11764", "CVE-2019-15903");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-03 18:33:48 +0000 (Fri, 03 Aug 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2872-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2872-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192872-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010406");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010421");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010425");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010426");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959933");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983922");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2019:2872-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox to 68.2.0 ESR fixes the following issues:

Mozilla Firefox was updated to version 68.2.0 ESR (bsc#1154738).

Security issues fixed:

- CVE-2019-15903: Fixed a heap overflow in the expat library (bsc#1149429).
- CVE-2019-11757: Fixed a use-after-free when creating index updates in IndexedDB (bsc#1154738).
- CVE-2019-11758: Fixed a potentially exploitable crash due to 360 Total Security (bsc#1154738).
- CVE-2019-11759: Fixed a stack buffer overflow in HKDF output (bsc#1154738).
- CVE-2019-11760: Fixed a stack buffer overflow in WebRTC networking (bsc#1154738).
- CVE-2019-11761: Fixed an unintended access to a privileged JSONView object (bsc#1154738).
- CVE-2019-11762: Fixed a same-origin-property violation (bsc#1154738).
- CVE-2019-11763: Fixed an XSS bypass (bsc#1154738).
- CVE-2019-11764: Fixed several memory safety bugs (bsc#1154738).

Non-security issues fixed:

- Firefox 60.7 ESR changed the user interface language (bsc#1137990).
- Wrong Firefox GUI Language (bsc#1120374).
- Fixed an inadvertent crash report transmission without user opt-in (bsc#1074235).
- Firefox hangs randomly when browsing and scrolling (bsc#1043008).
- Firefox stops loading page until mouse is moved (bsc#1025108).");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~68.2.0~109.95.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~68.2.0~109.95.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~68.2.0~109.95.2", rls:"SLES12.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~68.2.0~109.95.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~68.2.0~109.95.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~68.2.0~109.95.2", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~68.2.0~109.95.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~68.2.0~109.95.2", rls:"SLES12.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~68.2.0~109.95.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~68.2.0~109.95.2", rls:"SLES12.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~68.2.0~109.95.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~68.2.0~109.95.2", rls:"SLES12.0SP5"))) {
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

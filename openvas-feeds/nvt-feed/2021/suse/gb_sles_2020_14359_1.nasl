# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.14359.1");
  script_cve_id("CVE-2020-12387", "CVE-2020-12388", "CVE-2020-12389", "CVE-2020-12392", "CVE-2020-12393", "CVE-2020-12395", "CVE-2020-6831");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:03 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-28 16:38:04 +0000 (Thu, 28 May 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:14359-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:14359-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-202014359-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162828");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171186");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-May/006809.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2020:14359-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:


- Firefox Extended Support Release 68.8.0 ESR
 MFSA 2020-17 (bsc#1171186)
 * CVE-2020-12387 (bmo#1545345)
 Use-after-free during worker shutdown
 * CVE-2020-12388 (bmo#1618911)
 Sandbox escape with improperly guarded Access Tokens
 * CVE-2020-12389 (bmo#1554110)
 Sandbox escape with improperly separated process types
 * CVE-2020-6831 (bmo#1632241)
 Buffer overflow in SCTP chunk input validation
 * CVE-2020-12392 (bmo#1614468)
 Arbitrary local file access with 'Copy as cURL'
 * CVE-2020-12393 (bmo#1615471)
 Devtools' 'Copy as cURL' feature did not fully escape
 website-controlled data, potentially leading to command
 injection
 * CVE-2020-12395 (bmo#1595886, bmo#1611482, bmo#1614704,
 bmo#1624098, bmo#1625749, bmo#1626382, bmo#1628076,
 bmo#1631508)
 Memory safety bugs fixed in Firefox 76 and Firefox ESR 68.8

- Since firefox-gcc8 now has disabled autoreqprov for firefox-libstdc++6
 and firefox-libgcc_s1, those packages don't provide some capabilities,
 we have to disable AutoReqProv in MozillaFirefox too so they're not added as
 automatic requirements. (bsc#1162828)");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~68.8.0~78.73.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~68.8.0~78.73.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~68.8.0~78.73.1", rls:"SLES11.0SP4"))) {
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

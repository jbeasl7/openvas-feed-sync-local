# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0426.1");
  script_cve_id("CVE-2017-5373", "CVE-2017-5375", "CVE-2017-5376", "CVE-2017-5378", "CVE-2017-5380", "CVE-2017-5383", "CVE-2017-5386", "CVE-2017-5390", "CVE-2017-5396");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:01 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-02 19:54:49 +0000 (Thu, 02 Aug 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0426-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0426-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170426-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021817");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021819");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021991");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-February/002632.html");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-02/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2017:0426-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MozillaFirefox 45 ESR was updated to 45.7 to fix the following issues (bsc#1021991):

* MFSA 2017-02/CVE-2017-5378: Pointer and frame data leakage of Javascript objects (bsc#1021818)
* MFSA 2017-02/CVE-2017-5396: Use-after-free with Media Decoder (bsc#1021821)
* MFSA 2017-02/CVE-2017-5386: WebExtensions can use data: protocol to affect other extensions (bsc#1021823)
* MFSA 2017-02/CVE-2017-5380: Potential use-after-free during DOM manipulations (bsc#1021819)
* MFSA 2017-02/CVE-2017-5390: Insecure communication methods in Developer Tools JSON viewer (bsc#1021820)
* MFSA 2017-02/CVE-2017-5373: Memory safety bugs fixed in Firefox 51 and Firefox ESR 45.7 (bsc#1021824)
* MFSA 2017-02/CVE-2017-5375: Excessive JIT code allocation allows bypass of ASLR and DEP (bsc#1021814)
* MFSA 2017-02/CVE-2017-5376: Use-after-free in XSL (bsc#1021817)
* MFSA 2017-02/CVE-2017-5383: Location bar spoofing with unicode characters (bsc#1021822)

Please see [link moved to references]
for more information.");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~45.7.0esr~65.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~45.7.0esr~65.2", rls:"SLES11.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~45.7.0esr~65.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~45.7.0esr~65.2", rls:"SLES11.0SP4"))) {
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

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2131.1");
  script_cve_id("CVE-2016-2830", "CVE-2016-2835", "CVE-2016-2836", "CVE-2016-2837", "CVE-2016-2838", "CVE-2016-2839", "CVE-2016-5252", "CVE-2016-5254", "CVE-2016-5258", "CVE-2016-5259", "CVE-2016-5262", "CVE-2016-5263", "CVE-2016-5264", "CVE-2016-5265", "CVE-2016-6354");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-09-22 00:58:06 +0000 (Thu, 22 Sep 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2131-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2131-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162131-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/990628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/990856");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991809");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-August/002221.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2016:2131-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MozillaFirefox was updated to 45.3.0 ESR to fix the following issues
(bsc#991809):

* MFSA 2016-62/CVE-2016-2835/CVE-2016-2836
 Miscellaneous memory safety hazards (rv:48.0 / rv:45.3)
* MFSA 2016-63/CVE-2016-2830
 Favicon network connection can persist when page is closed
* MFSA 2016-64/CVE-2016-2838
 Buffer overflow rendering SVG with bidirectional content
* MFSA 2016-65/CVE-2016-2839
 Cairo rendering crash due to memory allocation issue with
 FFmpeg 0.10
* MFSA 2016-67/CVE-2016-5252
 Stack underflow during 2D graphics rendering
* MFSA 2016-70/CVE-2016-5254
 Use-after-free when using alt key and toplevel menus
* MFSA 2016-72/CVE-2016-5258
 Use-after-free in DTLS during WebRTC session shutdown
* MFSA 2016-73/CVE-2016-5259
 Use-after-free in service workers with nested sync events
* MFSA 2016-76/CVE-2016-5262
 Scripts on marquee tag can execute in sandboxed iframes
* MFSA 2016-77/CVE-2016-2837
 Buffer overflow in ClearKey Content Decryption Module (CDM)
 during video playback
* MFSA 2016-78/CVE-2016-5263
 Type confusion in display transformation
* MFSA 2016-79/CVE-2016-5264
 Use-after-free when applying SVG effects
* MFSA 2016-80/CVE-2016-5265
 Same-origin policy violation using local HTML file and saved
 shortcut file
* CVE-2016-6354: Fix for possible buffer overrun (bsc#990856)

Also a temporary workaround was added:
- Temporarily bind Firefox to the first CPU as a hotfix
 for an apparent race condition (bsc#989196, bsc#990628)");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~45.3.0esr~78.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~45.3.0esr~78.1", rls:"SLES12.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~45.3.0esr~78.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~45.3.0esr~78.1", rls:"SLES12.0SP1"))) {
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

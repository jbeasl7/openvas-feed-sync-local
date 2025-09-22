# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2434.1");
  script_cve_id("CVE-2016-5250", "CVE-2016-5257", "CVE-2016-5261", "CVE-2016-5270", "CVE-2016-5272", "CVE-2016-5274", "CVE-2016-5276", "CVE-2016-5277", "CVE-2016-5278", "CVE-2016-5280", "CVE-2016-5281", "CVE-2016-5284");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-09-23 14:13:35 +0000 (Fri, 23 Sep 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2434-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2434-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162434-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999701");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-October/002305.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2016:2434-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MozillaFirefox was updated to version 45.4.0 ESR to fix the following issues:

Security issues fixed: (bsc#999701 MFSA 2016-86):
* CVE-2016-5270: Heap-buffer-overflow in nsCaseTransformTextRunFactory::TransformString
* CVE-2016-5272: Bad cast in nsImageGeometryMixin
* CVE-2016-5276: Heap-use-after-free in mozilla::a11y::DocAccessible::ProcessInvalidationList
* CVE-2016-5274: use-after-free in nsFrameManager::CaptureFrameState
* CVE-2016-5277: Heap-use-after-free in nsRefreshDriver::Tick
* CVE-2016-5278: Heap-buffer-overflow in nsBMPEncoder::AddImageFrame
* CVE-2016-5280: Use-after-free in mozilla::nsTextNodeDirectionalityMap::RemoveElementFromMap
* CVE-2016-5281: use-after-free in DOMSVGLength
* CVE-2016-5284: Add-on update site certificate pin expiration
* CVE-2016-5250: Resource Timing API is storing resources sent by the previous page
* CVE-2016-5261: Integer overflow and memory corruption in WebSocketChannel
* CVE-2016-5257: Memory safety bugs fixed in Firefox 49 and Firefox ESR 45.4

Bug fixed:
- Fix for aarch64 Firefox startup crash (bsc#991344)");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~45.4.0esr~81.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~45.4.0esr~81.1", rls:"SLES12.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~45.4.0esr~81.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~45.4.0esr~81.1", rls:"SLES12.0SP1"))) {
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

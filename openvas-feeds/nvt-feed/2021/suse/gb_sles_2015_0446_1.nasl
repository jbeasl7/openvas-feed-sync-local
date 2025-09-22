# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0446.1");
  script_cve_id("CVE-2013-1701", "CVE-2013-1702", "CVE-2013-1705", "CVE-2013-1706", "CVE-2013-1707", "CVE-2013-1709", "CVE-2013-1710", "CVE-2013-1712", "CVE-2013-1713", "CVE-2013-1714", "CVE-2013-1717", "CVE-2013-1718", "CVE-2013-1722", "CVE-2013-1725", "CVE-2013-1726", "CVE-2013-1730", "CVE-2013-1732", "CVE-2013-1735", "CVE-2013-1736", "CVE-2013-1737", "CVE-2015-0822", "CVE-2015-0827", "CVE-2015-0831", "CVE-2015-0836");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:13 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0446-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0446-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150446-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/833389");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/840485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917300");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917597");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-March/001272.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla Firefox' package(s) announced via the SUSE-SU-2015:0446-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update to Firefox 17.0.9esr (bnc#840485) addresses:

 * MFSA 2013-91 User-defined properties on DOM proxies get the wrong
 'this' object
 o (CVE-2013-1737)
 * MFSA 2013-90 Memory corruption involving scrolling
 o use-after-free in mozilla::layout::ScrollbarActivity
 (CVE-2013-1735)
 o Memory corruption in nsGfxScrollFrameInner::IsLTR()
 (CVE-2013-1736)
 * MFSA 2013-89 Buffer overflow with multi-column, lists, and floats
 o buffer overflow at nsFloatManager::GetFlowArea() with multicol,
 list, floats (CVE-2013-1732)
 * MFSA 2013-88 compartment mismatch re-attaching XBL-backed nodes
 o compartment mismatch in nsXBLBinding::DoInitJSClass
 (CVE-2013-1730)
 * MFSA 2013-83 Mozilla Updater does not lock MAR file after signature
 verification
 o MAR signature bypass in Updater could lead to downgrade
 (CVE-2013-1726)
 * MFSA 2013-82 Calling scope for new Javascript objects can lead to
 memory corruption
 o ABORT: bad scope for new JSObjects: ReparentWrapper /
 document.open (CVE-2013-1725)
 * MFSA 2013-79 Use-after-free in Animation Manager during stylesheet
 cloning
 o Heap-use-after-free in nsAnimationManager::BuildAnimations
 (CVE-2013-1722)
 * MFSA 2013-76 Miscellaneous memory safety hazards (rv:24.0 /
 rv:17.0.9)
 o Memory safety bugs fixed in Firefox 17.0.9 and Firefox 24.0
 (CVE-2013-1718)
 * MFSA 2013-65 Buffer underflow when generating CRMF requests
 o ASAN heap-buffer-overflow (read 1) in
 cryptojs_interpret_key_gen_type (CVE-2013-1705)

Security Issue references:

 * CVE-2013-1737
 <[link moved to references]>
 * CVE-2013-1735
 <[link moved to references]>
 * CVE-2013-1736
 <[link moved to references]>
 * CVE-2013-1732
 <[link moved to references]>
 * CVE-2013-1730
 <[link moved to references]>
 * CVE-2013-1726
 <[link moved to references]>
 * CVE-2013-1725
 <[link moved to references]>
 * CVE-2013-1722
 <[link moved to references]>
 * CVE-2013-1718
 <[link moved to references]>
 * CVE-2013-1705
 <[link moved to references]>");

  script_tag(name:"affected", value:"'Mozilla Firefox' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~17.0.9esr~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~17.0.9esr~0.7.1", rls:"SLES11.0SP3"))) {
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

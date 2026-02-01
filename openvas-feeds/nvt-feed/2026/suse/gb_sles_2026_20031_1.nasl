# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20031.1");
  script_cve_id("CVE-2025-14321", "CVE-2025-14322", "CVE-2025-14323", "CVE-2025-14324", "CVE-2025-14325", "CVE-2025-14328", "CVE-2025-14329", "CVE-2025-14330", "CVE-2025-14331", "CVE-2025-14333");
  script_tag(name:"creation_date", value:"2026-01-16 04:26:57 +0000 (Fri, 16 Jan 2026)");
  script_version("2026-01-28T05:49:43+0000");
  script_tag(name:"last_modification", value:"2026-01-28 05:49:43 +0000 (Wed, 28 Jan 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-10 20:22:53 +0000 (Wed, 10 Dec 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20031-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20031-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620031-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254551");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023773.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2026:20031-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

Changes in MozillaFirefox:

Firefox Extended Support Release 140.6.0 ESR was released:

* Fixed: Various security fixes.

MFSA 2025-94 (bsc#1254551):

 * CVE-2025-14321: Use-after-free in the WebRTC: Signaling component
 * CVE-2025-14322: Sandbox escape due to incorrect boundary conditions in the Graphics: CanvasWebGL component
 * CVE-2025-14323: Privilege escalation in the DOM: Notifications component
 * CVE-2025-14324: JIT miscompilation in the JavaScript Engine: JIT component
 * CVE-2025-14325: JIT miscompilation in the JavaScript Engine: JIT component
 * CVE-2025-14328: Privilege escalation in the Netmonitor component
 * CVE-2025-14329: Privilege escalation in the Netmonitor component
 * CVE-2025-14330: JIT miscompilation in the JavaScript Engine: JIT component
 * CVE-2025-14331: Same-origin policy bypass in the Request Handling component
 * CVE-2025-14333: Memory safety bugs fixed in Firefox ESR 140.6, Thunderbird ESR 140.6, Firefox 146 and Thunderbird 146");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~140.6.0~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~140.6.0~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~140.6.0~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~140.6.0~160000.1.1", rls:"SLES16.0.0"))) {
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

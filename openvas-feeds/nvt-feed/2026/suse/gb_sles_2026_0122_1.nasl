# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0122.1");
  script_cve_id("CVE-2025-14327", "CVE-2026-0877", "CVE-2026-0878", "CVE-2026-0879", "CVE-2026-0880", "CVE-2026-0882", "CVE-2026-0883", "CVE-2026-0884", "CVE-2026-0885", "CVE-2026-0886", "CVE-2026-0887", "CVE-2026-0890", "CVE-2026-0891");
  script_tag(name:"creation_date", value:"2026-01-16 04:26:57 +0000 (Fri, 16 Jan 2026)");
  script_version("2026-01-16T05:47:38+0000");
  script_tag(name:"last_modification", value:"2026-01-16 05:47:38 +0000 (Fri, 16 Jan 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-10 20:29:43 +0000 (Wed, 10 Dec 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0122-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0122-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260122-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256340");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023741.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2026:0122-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

Update to Firefox Extended Support Release 140.7.0 ESR (bsc#1256340).

- MFSA 2026-03
 * CVE-2026-0877: Mitigation bypass in the DOM: Security component
 * CVE-2026-0878: Sandbox escape due to incorrect boundary conditions in the Graphics: CanvasWebGL component
 * CVE-2026-0879: Sandbox escape due to incorrect boundary conditions in the Graphics component
 * CVE-2026-0880: Sandbox escape due to integer overflow in the Graphics component
 * CVE-2026-0882: Use-after-free in the IPC component
 * CVE-2025-14327: Spoofing issue in the Downloads Panel component
 * CVE-2026-0883: Information disclosure in the Networking component
 * CVE-2026-0884: Use-after-free in the JavaScript Engine component
 * CVE-2026-0885: Use-after-free in the JavaScript: GC component
 * CVE-2026-0886: Incorrect boundary conditions in the Graphics component
 * CVE-2026-0887: Clickjacking issue, information disclosure in the PDF Viewer component
 * CVE-2026-0890: Spoofing issue in the DOM: Copy-Paste and Drag-Drop component
 * CVE-2026-0891: Memory safety bugs fixed in Firefox ESR 140.7, Thunderbird ESR 140.7, Firefox 147 and Thunderbird 147");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~140.7.0~112.295.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~140.7.0~112.295.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~140.7.0~112.295.1", rls:"SLES12.0SP5"))) {
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

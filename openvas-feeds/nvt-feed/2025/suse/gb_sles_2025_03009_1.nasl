# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.03009.1");
  script_cve_id("CVE-2025-9179", "CVE-2025-9180", "CVE-2025-9181", "CVE-2025-9182", "CVE-2025-9183", "CVE-2025-9184", "CVE-2025-9185", "CVE-2025-9187");
  script_tag(name:"creation_date", value:"2025-09-01 04:17:40 +0000 (Mon, 01 Sep 2025)");
  script_version("2025-09-01T05:39:44+0000");
  script_tag(name:"last_modification", value:"2025-09-01 05:39:44 +0000 (Mon, 01 Sep 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-21 18:28:45 +0000 (Thu, 21 Aug 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:03009-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03009-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503009-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248162");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041409.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2025:03009-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

- Firefox Extended Support Release 140.2.0 ESR
 MFSA 2025-67 (bsc#1248162)
 * CVE-2025-9179 (bmo#1979527):
 Sandbox escape due to invalid pointer in the Audio/Video: GMP
 component
 * CVE-2025-9180 (bmo#1979782):
 Same-origin policy bypass in the Graphics: Canvas2D component
 * CVE-2025-9181 (bmo#1977130):
 Uninitialized memory in the JavaScript Engine component
 * CVE-2025-9182 (bmo#1975837):
 Denial-of-service due to out-of-memory in the Graphics:
 WebRender component
 * CVE-2025-9183 (bmo#1976102):
 Spoofing issue in the Address Bar component
 * CVE-2025-9184 (bmo#1929482, bmo#1976376, bmo#1979163,
 bmo#1979955):
 Memory safety bugs fixed in Firefox ESR 140.2, Thunderbird
 ESR 140.2, Firefox 142 and Thunderbird 142
 * CVE-2025-9185 (bmo#1970154, bmo#1976782, bmo#1977166):
 Memory safety bugs fixed in Firefox ESR 115.27, Firefox ESR
 128.14, Thunderbird ESR 128.14, Firefox ESR 140.2,
 Thunderbird ESR 140.2, Firefox 142 and Thunderbird 142
 * CVE-2025-9187 (bmo#1825621, bmo#1970079, bmo#1976736,
 bmo#1979072): Memory safety bugs fixed in Firefox 142 and
 Thunderbird 142

- Other fixes:
 * Ensure the use of the correct file-picker on KDE (bsc#1226112)");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~140.2.0~112.276.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~140.2.0~112.276.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~140.2.0~112.276.1", rls:"SLES12.0SP5"))) {
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

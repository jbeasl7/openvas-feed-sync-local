# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833094");
  script_cve_id("CVE-2023-50761", "CVE-2023-50762", "CVE-2023-6856", "CVE-2023-6857", "CVE-2023-6858", "CVE-2023-6859", "CVE-2023-6860", "CVE-2023-6861", "CVE-2023-6862", "CVE-2023-6863", "CVE-2023-6864");
  script_tag(name:"creation_date", value:"2024-03-04 12:52:25 +0000 (Mon, 04 Mar 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-22 10:59:57 +0000 (Fri, 22 Dec 2023)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:0044-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0044-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240044-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217974");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-January/017601.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird' package(s) announced via the SUSE-SU-2024:0044-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

Firefox Extended Support Release 115.6.0 ESR (bsc#1217974):
 * CVE-2023-6856: Heap-buffer-overflow affecting WebGL DrawElementsInstanced method with Mesa VM driver (bmo#1843782).
 * CVE-2023-6857: Symlinks may resolve to smaller than expected buffers (bmo#1796023).
 * CVE-2023-6858: Heap buffer overflow in nsTextFragment (bmo#1826791).
 * CVE-2023-6859: Use-after-free in PR_GetIdentitiesLayer (bmo#1840144).
 * CVE-2023-6860: Potential sandbox escape due to VideoBridge lack of texture validation (bmo#1854669).
 * CVE-2023-6861: Heap buffer overflow affected nsWindow::PickerOpen(void) in headless mode (bmo#1864118).
 * CVE-2023-6862: Use-after-free in nsDNSService (bsc#1868042).
 * CVE-2023-6863: Undefined behavior in ShutdownObserver() (bmo#1868901).
 * CVE-2023-6864: Memory safety bugs fixed in Firefox 121, Firefox ESR 115.6, and Thunderbird 115.6.
 * CVE-2023-50762: Truncated signed text was shown with a valid OpenPGP signature (bmo#1862625).");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~115.6.0~150200.8.142.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~115.6.0~150200.8.142.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~115.6.0~150200.8.142.2", rls:"openSUSELeap15.5"))) {
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

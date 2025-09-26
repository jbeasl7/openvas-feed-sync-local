# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03300.1");
  script_cve_id("CVE-2025-53905", "CVE-2025-53906", "CVE-2025-55157", "CVE-2025-55158");
  script_tag(name:"creation_date", value:"2025-09-25 04:06:57 +0000 (Thu, 25 Sep 2025)");
  script_version("2025-09-25T05:39:09+0000");
  script_tag(name:"last_modification", value:"2025-09-25 05:39:09 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-12 18:49:05 +0000 (Tue, 12 Aug 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03300-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03300-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503300-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246602");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247939");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041803.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the SUSE-SU-2025:03300-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for vim fixes the following issues:

Updated to 9.1.1629:
- CVE-2025-53905: Fixed malicious tar archive may causing a path traversal in Vim's tar.vim plugin (bsc#1246604)
- CVE-2025-53906: Fixed malicious zip archive may causing a path traversal in Vim's zip (bsc#1246602)
- CVE-2025-55157: Fixed use-after-free in internal tuple reference management (bsc#1247938)
- CVE-2025-55158: Fixed double-free in internal typed value (typval_T) management (bsc#1247939)");

  script_tag(name:"affected", value:"'vim' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~9.1.1629~150500.20.33.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~9.1.1629~150500.20.33.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~9.1.1629~150500.20.33.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~9.1.1629~150500.20.33.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small", rpm:"vim-small~9.1.1629~150500.20.33.1", rls:"openSUSELeap15.6"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.0723.1");
  script_cve_id("CVE-2024-43790", "CVE-2024-43802", "CVE-2024-45306", "CVE-2025-1215", "CVE-2025-22134", "CVE-2025-24014");
  script_tag(name:"creation_date", value:"2025-02-28 04:06:21 +0000 (Fri, 28 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-13 17:28:19 +0000 (Wed, 13 Aug 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0723-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0723-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250723-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236151");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237137");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-February/020448.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the SUSE-SU-2025:0723-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for vim fixes the following issues:

Update to version 9.1.1101:

- CVE-2024-43790: possible out-of-bounds read when performing a search command (bsc#1229685).
- CVE-2024-43802: heap buffer overflow due to incorrect flushing of the typeahead buffer (bsc#1229822).
- CVE-2024-45306: heap buffer overflow when cursor position is invalid (bsc#1230078).
- CVE-2025-22134: heap buffer overflow when switching to other buffers using the :all command with active visual mode
 (bsc#1235695).
- CVE-2025-24014: NULL pointer dereference may lead to segmentation fault when in silent Ex mode (bsc#1236151).
- CVE-2025-1215: memory corruption when manipulating the --log argument (bsc#1237137).");

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

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~9.1.1101~150500.20.21.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~9.1.1101~150500.20.21.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~9.1.1101~150500.20.21.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~9.1.1101~150500.20.21.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small", rpm:"vim-small~9.1.1101~150500.20.21.1", rls:"openSUSELeap15.6"))) {
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

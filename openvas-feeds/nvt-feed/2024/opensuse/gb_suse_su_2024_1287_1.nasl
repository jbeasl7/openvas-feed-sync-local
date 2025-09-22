# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856073");
  script_cve_id("CVE-2023-4750", "CVE-2023-48231", "CVE-2023-48232", "CVE-2023-48233", "CVE-2023-48234", "CVE-2023-48235", "CVE-2023-48236", "CVE-2023-48237", "CVE-2023-48706", "CVE-2024-22667");
  script_tag(name:"creation_date", value:"2024-04-17 01:01:15 +0000 (Wed, 17 Apr 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-05 17:29:53 +0000 (Wed, 05 Feb 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:1287-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1287-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241287-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215005");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217316");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217321");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217324");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217326");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217329");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219581");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-April/018354.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the SUSE-SU-2024:1287-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for vim fixes the following issues:

Updated to version 9.1.0111, fixes the following security problems

- CVE-2023-48231: Use-After-Free in win_close() (bsc#1217316).
- CVE-2023-48232: Floating point Exception in adjust_plines_for_skipcol() (bsc#1217320).
- CVE-2023-48233: overflow with count for :s command (bsc#1217321).
- CVE-2023-48234: overflow in nv_z_get_count (bsc#1217324).
- CVE-2023-48235: overflow in ex address parsing (CVE-2023-48235).
- CVE-2023-48236: overflow in get_number (bsc#1217329).
- CVE-2023-48237: overflow in shift_line (bsc#1217330).
- CVE-2023-48706: heap-use-after-free in ex_substitute (bsc#1217432).
- CVE-2024-22667: stack-based buffer overflow in did_set_langmap function in map.c (bsc#1219581).
- CVE-2023-4750: Heap use-after-free in function bt_quickfix (bsc#1215005).");

  script_tag(name:"affected", value:"'vim' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~9.1.0111~150500.20.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~9.1.0111~150500.20.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~9.1.0111~150500.20.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~9.1.0111~150500.20.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small", rpm:"vim-small~9.1.0111~150500.20.9.1", rls:"openSUSELeap15.5"))) {
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

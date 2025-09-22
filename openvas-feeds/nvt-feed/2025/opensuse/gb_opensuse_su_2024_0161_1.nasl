# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2024.0161.1");
  script_cve_id("CVE-2024-36041");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-08 16:46:20 +0000 (Mon, 08 Jul 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0161-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0161-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VXFL4FV75KKEUKXI3LJ5OTFGTIP4IVYA/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/487912");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'plasma5-workspace' package(s) announced via the openSUSE-SU-2024:0161-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"plasma5-workspace was updated to fix the following issue:


- Fixed ksmserver authentication (CVE-2024-36041, boo#1225774).

- Fixed a regression introduced by the preceding change (kde#487912, boo#1226110):");

  script_tag(name:"affected", value:"'plasma5-workspace' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"gmenudbusmenuproxy", rpm:"gmenudbusmenuproxy~5.27.11~bp156.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma5-session", rpm:"plasma5-session~5.27.11~bp156.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma5-session-wayland", rpm:"plasma5-session-wayland~5.27.11~bp156.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma5-workspace", rpm:"plasma5-workspace~5.27.11~bp156.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma5-workspace-devel", rpm:"plasma5-workspace-devel~5.27.11~bp156.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma5-workspace-lang", rpm:"plasma5-workspace-lang~5.27.11~bp156.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plasma5-workspace-libs", rpm:"plasma5-workspace-libs~5.27.11~bp156.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xembedsniproxy", rpm:"xembedsniproxy~5.27.11~bp156.3.3.1", rls:"openSUSELeap15.6"))) {
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

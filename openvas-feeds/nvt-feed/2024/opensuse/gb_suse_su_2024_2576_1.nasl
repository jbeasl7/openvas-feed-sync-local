# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856330");
  script_cve_id("CVE-2023-43090", "CVE-2024-36472");
  script_tag(name:"creation_date", value:"2024-07-24 04:00:58 +0000 (Wed, 24 Jul 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-26 13:10:22 +0000 (Tue, 26 Sep 2023)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:2576-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2576-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242576-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225567");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-July/036098.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnome-shell' package(s) announced via the SUSE-SU-2024:2576-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gnome-shell fixes the following issues:

- CVE-2024-36472: Fixed portal helper automatically launched without user confirmation (bsc#1225567)");

  script_tag(name:"affected", value:"'gnome-shell' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"gnome-extensions", rpm:"gnome-extensions~45.3~150600.5.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell", rpm:"gnome-shell~45.3~150600.5.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell-calendar", rpm:"gnome-shell-calendar~45.3~150600.5.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell-devel", rpm:"gnome-shell-devel~45.3~150600.5.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell-lang", rpm:"gnome-shell-lang~45.3~150600.5.6.1", rls:"openSUSELeap15.6"))) {
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

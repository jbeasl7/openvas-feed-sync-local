# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.1838.1");
  script_cve_id("CVE-2024-3727");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-14 15:42:07 +0000 (Tue, 14 May 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:1838-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1838-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241838-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224124");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225402");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-May/035406.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'warewulf4' package(s) announced via the SUSE-SU-2024:1838-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for warewulf4 fixes the following issues:

- fixed wwctl configure --all doesn't configure ssh (bsc#1225402)

- update to 4.5.2 with following changes:
 * Reorder dnsmasq config to put iPXE last
 * Update go-digest dependency to fix
 CVE-2024-3727: digest values not always validated (bsc#1224124)

- updated to version 4.5.1 with following changes
 * wwctl [profile<pipe>node] list -a handles now slices correclty
 * Fix a locking issue with concurrent read/writes for node status

- Remove API package as use of this wasn't documented

- use tftp.socket for activation (bsc#1216994)");

  script_tag(name:"affected", value:"'warewulf4' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"warewulf4", rpm:"warewulf4~4.5.2~150500.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"warewulf4-man", rpm:"warewulf4-man~4.5.2~150500.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"warewulf4-overlay", rpm:"warewulf4-overlay~4.5.2~150500.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"warewulf4-overlay-slurm", rpm:"warewulf4-overlay-slurm~4.5.2~150500.6.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"warewulf4", rpm:"warewulf4~4.5.2~150500.6.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"warewulf4-man", rpm:"warewulf4-man~4.5.2~150500.6.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"warewulf4-overlay", rpm:"warewulf4-overlay~4.5.2~150500.6.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"warewulf4-overlay-slurm", rpm:"warewulf4-overlay-slurm~4.5.2~150500.6.13.1", rls:"openSUSELeap15.6"))) {
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

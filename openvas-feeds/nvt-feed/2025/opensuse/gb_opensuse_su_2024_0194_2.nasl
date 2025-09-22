# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2024.0194.2");
  script_cve_id("CVE-2023-29408");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-07 18:15:10 +0000 (Mon, 07 Aug 2023)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0194-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0194-2");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PKFUM343ZIFFU5562L2AAJWE2OVIJBOH/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213928");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'keybase-client' package(s) announced via the openSUSE-SU-2024:0194-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for keybase-client fixes the following issues:

Update to version 6.2.8


 * Update client CA
 * Fix incomplete locking in config file handling.

- Update the Image dependency to address CVE-2023-29408 /
 boo#1213928. This is done via the new update-image-tiff.patch.
- Limit parallel test execution as that seems to cause failing
 builds on OBS that don't occur locally.
- Integrate KBFS packages previously build via own source package
 * Upstream integrated these into the same source.
 * Also includes adding kbfs-related patches
 ensure-mount-dir-exists.patch and
 ensure-service-stop-unmounts-filesystem.patch.
- Upgrade Go version used for compilation to 1.19.
- Use Systemd unit file from upstream source.");

  script_tag(name:"affected", value:"'keybase-client' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"kbfs", rpm:"kbfs~6.2.8~bp156.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kbfs-git", rpm:"kbfs-git~6.2.8~bp156.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kbfs-tool", rpm:"kbfs-tool~6.2.8~bp156.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keybase-client", rpm:"keybase-client~6.2.8~bp156.2.3.1", rls:"openSUSELeap15.5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kbfs", rpm:"kbfs~6.2.8~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kbfs-git", rpm:"kbfs-git~6.2.8~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kbfs-tool", rpm:"kbfs-tool~6.2.8~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keybase-client", rpm:"keybase-client~6.2.8~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
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

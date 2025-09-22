# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833570");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-34058", "CVE-2023-34059");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-07 21:07:45 +0000 (Tue, 07 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:32:05 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for open (SUSE-SU-2023:4227-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5|openSUSELeapMicro5\.3|openSUSELeap15\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4227-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/WETLXSNIRNG25NZMCZDTGLSO5Y32DJOO");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'open'
  package(s) announced via the SUSE-SU-2023:4227-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for open-vm-tools fixes the following issues:

  * CVE-2023-34058: Fixed a SAML token signature bypass issue (bsc#1216432).

  * CVE-2023-34059: Fixed a privilege escalation issue through vmware-user-suid-
      wrapper (bsc#1216433).

  ##");

  script_tag(name:"affected", value:"'open' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-containerinfo-debuginfo", rpm:"open-vm-tools-containerinfo-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools", rpm:"open-vm-tools~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop", rpm:"open-vm-tools-desktop~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools-devel", rpm:"libvmtools-devel~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-sdmp-debuginfo", rpm:"open-vm-tools-sdmp-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop-debuginfo", rpm:"open-vm-tools-desktop-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-sdmp", rpm:"open-vm-tools-sdmp~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0-debuginfo", rpm:"libvmtools0-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-debugsource", rpm:"open-vm-tools-debugsource~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0", rpm:"libvmtools0~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-debuginfo", rpm:"open-vm-tools-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-containerinfo", rpm:"open-vm-tools-containerinfo~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-salt-minion", rpm:"open-vm-tools-salt-minion~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-containerinfo-debuginfo", rpm:"open-vm-tools-containerinfo-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools", rpm:"open-vm-tools~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop", rpm:"open-vm-tools-desktop~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools-devel", rpm:"libvmtools-devel~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-sdmp-debuginfo", rpm:"open-vm-tools-sdmp-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop-debuginfo", rpm:"open-vm-tools-desktop-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-sdmp", rpm:"open-vm-tools-sdmp~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0-debuginfo", rpm:"libvmtools0-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-debugsource", rpm:"open-vm-tools-debugsource~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0", rpm:"libvmtools0~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-debuginfo", rpm:"open-vm-tools-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-containerinfo", rpm:"open-vm-tools-containerinfo~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-salt-minion", rpm:"open-vm-tools-salt-minion~12.3.0~150300.43.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-containerinfo-debuginfo", rpm:"open-vm-tools-containerinfo-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools", rpm:"open-vm-tools~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop", rpm:"open-vm-tools-desktop~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools-devel", rpm:"libvmtools-devel~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-sdmp-debuginfo", rpm:"open-vm-tools-sdmp-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop-debuginfo", rpm:"open-vm-tools-desktop-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-sdmp", rpm:"open-vm-tools-sdmp~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0-debuginfo", rpm:"libvmtools0-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-debugsource", rpm:"open-vm-tools-debugsource~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0", rpm:"libvmtools0~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-debuginfo", rpm:"open-vm-tools-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-containerinfo", rpm:"open-vm-tools-containerinfo~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-salt-minion", rpm:"open-vm-tools-salt-minion~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-containerinfo-debuginfo", rpm:"open-vm-tools-containerinfo-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools", rpm:"open-vm-tools~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop", rpm:"open-vm-tools-desktop~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools-devel", rpm:"libvmtools-devel~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-sdmp-debuginfo", rpm:"open-vm-tools-sdmp-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop-debuginfo", rpm:"open-vm-tools-desktop-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-sdmp", rpm:"open-vm-tools-sdmp~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0-debuginfo", rpm:"libvmtools0-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-debugsource", rpm:"open-vm-tools-debugsource~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0", rpm:"libvmtools0~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-debuginfo", rpm:"open-vm-tools-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-containerinfo", rpm:"open-vm-tools-containerinfo~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-salt-minion", rpm:"open-vm-tools-salt-minion~12.3.0~150300.43.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.3") {

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools", rpm:"open-vm-tools~12.3.0~150300.43.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0-debuginfo", rpm:"libvmtools0-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-debugsource", rpm:"open-vm-tools-debugsource~12.3.0~150300.43.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0", rpm:"libvmtools0~12.3.0~150300.43.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-debuginfo", rpm:"open-vm-tools-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-containerinfo-debuginfo", rpm:"open-vm-tools-containerinfo-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools", rpm:"open-vm-tools~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop", rpm:"open-vm-tools-desktop~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools-devel", rpm:"libvmtools-devel~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-sdmp-debuginfo", rpm:"open-vm-tools-sdmp-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop-debuginfo", rpm:"open-vm-tools-desktop-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-sdmp", rpm:"open-vm-tools-sdmp~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0-debuginfo", rpm:"libvmtools0-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-debugsource", rpm:"open-vm-tools-debugsource~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0", rpm:"libvmtools0~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-debuginfo", rpm:"open-vm-tools-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-containerinfo", rpm:"open-vm-tools-containerinfo~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-salt-minion", rpm:"open-vm-tools-salt-minion~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-containerinfo-debuginfo", rpm:"open-vm-tools-containerinfo-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools", rpm:"open-vm-tools~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop", rpm:"open-vm-tools-desktop~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools-devel", rpm:"libvmtools-devel~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-sdmp-debuginfo", rpm:"open-vm-tools-sdmp-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop-debuginfo", rpm:"open-vm-tools-desktop-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-sdmp", rpm:"open-vm-tools-sdmp~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0-debuginfo", rpm:"libvmtools0-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-debugsource", rpm:"open-vm-tools-debugsource~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0", rpm:"libvmtools0~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-debuginfo", rpm:"open-vm-tools-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-containerinfo", rpm:"open-vm-tools-containerinfo~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-salt-minion", rpm:"open-vm-tools-salt-minion~12.3.0~150300.43.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.4") {

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools", rpm:"open-vm-tools~12.3.0~150300.43.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0-debuginfo", rpm:"libvmtools0-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-debugsource", rpm:"open-vm-tools-debugsource~12.3.0~150300.43.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0", rpm:"libvmtools0~12.3.0~150300.43.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-debuginfo", rpm:"open-vm-tools-debuginfo~12.3.0~150300.43.1", rls:"openSUSELeapMicro5.4"))) {
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
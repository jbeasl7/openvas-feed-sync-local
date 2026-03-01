# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0414.1");
  script_cve_id("CVE-2026-21925", "CVE-2026-21932", "CVE-2026-21933", "CVE-2026-21945");
  script_tag(name:"creation_date", value:"2026-02-11 14:06:41 +0000 (Wed, 11 Feb 2026)");
  script_version("2026-02-12T05:59:59+0000");
  script_tag(name:"last_modification", value:"2026-02-12 05:59:59 +0000 (Thu, 12 Feb 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-20 22:15:57 +0000 (Tue, 20 Jan 2026)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0414-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0414-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260414-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257038");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024088.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-11-openjdk' package(s) announced via the SUSE-SU-2026:0414-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2026-21925: Fixed Oracle Java SE component RMI (bsc#1257034).
- CVE-2026-21932: Fixed Oracle Java SE component AWT and JavaFX (bsc#1257036).
- CVE-2026-21933: Fixed Oracle Java SE component Networking (bsc#1257037).
- CVE-2026-21945: Fixed Oracle Java SE component Security (bsc#1257038).

Other fixes:

- OpenJDK rendering blue borders when it should not, due to missing the fix for JDK-6304250 from upstream (bsc#1255446).
- Do not depend on update-desktop-files (jsc#PED-14507).");

  script_tag(name:"affected", value:"'java-11-openjdk' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.30.0~150000.3.135.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.30.0~150000.3.135.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.30.0~150000.3.135.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.30.0~150000.3.135.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-javadoc", rpm:"java-11-openjdk-javadoc~11.0.30.0~150000.3.135.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-jmods", rpm:"java-11-openjdk-jmods~11.0.30.0~150000.3.135.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-src", rpm:"java-11-openjdk-src~11.0.30.0~150000.3.135.1", rls:"openSUSELeap15.6"))) {
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

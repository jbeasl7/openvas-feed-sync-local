# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.1091.1");
  script_cve_id("CVE-2025-32801", "CVE-2025-32802", "CVE-2025-32803");
  script_tag(name:"creation_date", value:"2026-03-30 04:57:45 +0000 (Mon, 30 Mar 2026)");
  script_version("2026-03-30T06:15:36+0000");
  script_tag(name:"last_modification", value:"2026-03-30 06:15:36 +0000 (Mon, 30 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-28 17:15:23 +0000 (Wed, 28 May 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:1091-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1091-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261091-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243240");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024966.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kea' package(s) announced via the SUSE-SU-2026:1091-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kea fixes the following issues:

Update to release 2.6.3 (bsc#1243240):

- CVE-2025-32801: Fixed loading a malicious hook library can lead to local privilege escalation.
- CVE-2025-32802: Fixed insecure handling of file paths allows multiple local attacks.
- CVE-2025-32803: Fixed insecure file permissions can result in confidential information leakage.");

  script_tag(name:"affected", value:"'kea' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"kea", rpm:"kea~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-devel", rpm:"kea-devel~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-doc", rpm:"kea-doc~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-hooks", rpm:"kea-hooks~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-asiodns49", rpm:"libkea-asiodns49~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-asiolink72", rpm:"libkea-asiolink72~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-cc68", rpm:"libkea-cc68~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-cfgclient66", rpm:"libkea-cfgclient66~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-cryptolink50", rpm:"libkea-cryptolink50~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-d2srv47", rpm:"libkea-d2srv47~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-database62", rpm:"libkea-database62~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-dhcp++92", rpm:"libkea-dhcp++92~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-dhcp_ddns57", rpm:"libkea-dhcp_ddns57~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-dhcpsrv111", rpm:"libkea-dhcpsrv111~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-dns++57", rpm:"libkea-dns++57~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-eval69", rpm:"libkea-eval69~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-exceptions33", rpm:"libkea-exceptions33~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-hooks100", rpm:"libkea-hooks100~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-http72", rpm:"libkea-http72~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-log61", rpm:"libkea-log61~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-mysql71", rpm:"libkea-mysql71~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-pgsql71", rpm:"libkea-pgsql71~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-process74", rpm:"libkea-process74~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-stats41", rpm:"libkea-stats41~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-tcp19", rpm:"libkea-tcp19~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-util-io0", rpm:"libkea-util-io0~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkea-util86", rpm:"libkea-util86~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-kea", rpm:"python3-kea~2.6.3~150600.13.6.1", rls:"openSUSELeap15.6"))) {
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

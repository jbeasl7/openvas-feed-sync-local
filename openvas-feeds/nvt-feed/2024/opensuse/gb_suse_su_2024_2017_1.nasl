# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856397");
  script_version("2025-03-12T05:38:19+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-12 05:38:19 +0000 (Wed, 12 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-08-28 04:01:24 +0000 (Wed, 28 Aug 2024)");
  script_name("openSUSE: Security Advisory for roundcubemail(SUSE-RU-2024:2017-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeapMicro5\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-RU-2024:2017-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TNVRYI54RWIXEEH3FO2E2FNNB3PNQ4KE");

  script_tag(name:"summary", value:"The remote host is missing an update for the roundcubemail
  package(s) announced via the SUSE-RU-2024:2017-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for transactional-update fixes the following
  issues Properly handle overlay syncing failures: If the system would not be rebooted
  and several snapshots accumulated in the meantime, it was possible that the previous
  base snapshot 'required for /etc syncing' was deleted already.");

  script_tag(name:"affected", value:"roundcubemail package(s) on openSUSE Leap Micro 5.3.");

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

if(release == "openSUSELeapMicro5.3") {

  if(!isnull(res = isrpmvuln(pkg:"transactional-update-zypp-config", rpm:"transactional-update-zypp-config~4.1.8~150400.3.9.3", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dracut-transactional-update", rpm:"dracut-transactional-update~4.1.8~150400.3.9.3", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tukitd-debuginfo", rpm:"tukitd-debuginfo~4.1.8~150400.3.9.3", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtukit4-debuginfo", rpm:"libtukit4-debuginfo~4.1.8~150400.3.9.3", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tukit", rpm:"tukit~4.1.8~150400.3.9.3", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tukitd", rpm:"tukitd~4.1.8~150400.3.9.3", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"transactional-update-debugsource", rpm:"transactional-update-debugsource~4.1.8~150400.3.9.3", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"transactional-update-debuginfo", rpm:"transactional-update-debuginfo~4.1.8~150400.3.9.3", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtukit4", rpm:"libtukit4~4.1.8~150400.3.9.3", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tukit-debuginfo", rpm:"tukit-debuginfo~4.1.8~150400.3.9.3", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"transactional-update", rpm:"transactional-update~4.1.8~150400.3.9.3", rls:"openSUSELeapMicro5.3"))) {
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

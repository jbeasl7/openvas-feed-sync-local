# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833525");
  script_version("2025-03-12T05:38:19+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-12 05:38:19 +0000 (Wed, 12 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-03-04 07:11:56 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for sbd (SUSE-SU-2023:0002-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0002-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6J3QEBZGTR7WNXJTVNQQ4JMTAFVSBDXM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sbd'
  package(s) announced via the SUSE-SU-2023:0002-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sbd fixes the following issues:

     Update to version 1.5.1+20221128.8ec8e01:

  - sbd-inquisitor: fail startup if pacemaker integration is disabled while
       SBD_SYNC_RESOURCE_STARTUP is conflicting (bsc#1204319)

  - sbd-inquisitor: do not warn about startup syncing if pacemaker
       integration is even intentionally disabled (bsc#1204319)

  - sbd-inquisitor: log a warning if SBD_PACEMAKER is overridden by -P or

  - PP option (bsc#1204319)

  - sbd-inquisitor: ensure a log info only tells the fact about how
       SBD_PACEMAKER is set (bsc#1204319)

  - Added hardened to systemd service(s) (bsc#1181400).");

  script_tag(name:"affected", value:"'sbd' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"sbd", rpm:"sbd~1.5.1+20221128.8ec8e01~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbd-debuginfo", rpm:"sbd-debuginfo~1.5.1+20221128.8ec8e01~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbd-debugsource", rpm:"sbd-debugsource~1.5.1+20221128.8ec8e01~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbd-devel", rpm:"sbd-devel~1.5.1+20221128.8ec8e01~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbd-devel-debuginfo", rpm:"sbd-devel-debuginfo~1.5.1+20221128.8ec8e01~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbd", rpm:"sbd~1.5.1+20221128.8ec8e01~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbd-debuginfo", rpm:"sbd-debuginfo~1.5.1+20221128.8ec8e01~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbd-debugsource", rpm:"sbd-debugsource~1.5.1+20221128.8ec8e01~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbd-devel", rpm:"sbd-devel~1.5.1+20221128.8ec8e01~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbd-devel-debuginfo", rpm:"sbd-devel-debuginfo~1.5.1+20221128.8ec8e01~150400.3.3.1", rls:"openSUSELeap15.4"))) {
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

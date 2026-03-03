# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0661.1");
  script_cve_id("CVE-2025-48038", "CVE-2025-48039", "CVE-2025-48040");
  script_tag(name:"creation_date", value:"2026-03-02 04:36:59 +0000 (Mon, 02 Mar 2026)");
  script_version("2026-03-02T05:55:30+0000");
  script_tag(name:"last_modification", value:"2026-03-02 05:55:30 +0000 (Mon, 02 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0661-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0661-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260661-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249469");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249470");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249472");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024449.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'erlang' package(s) announced via the SUSE-SU-2026:0661-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for erlang fixes the following issues:

- CVE-2025-48039:Fixed an excessive use of system resources. (bsc#1249469)
- CVE-2025-48038:Fixed an excessive use of system resources. (bsc#1249470)
- CVE-2025-48040:Fixed an excessive resource consumption. (bsc#1249472)");

  script_tag(name:"affected", value:"'erlang' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"erlang", rpm:"erlang~23.3.4.19~150300.3.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-debugger", rpm:"erlang-debugger~23.3.4.19~150300.3.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-debugger-src", rpm:"erlang-debugger-src~23.3.4.19~150300.3.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-dialyzer", rpm:"erlang-dialyzer~23.3.4.19~150300.3.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-dialyzer-src", rpm:"erlang-dialyzer-src~23.3.4.19~150300.3.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-diameter", rpm:"erlang-diameter~23.3.4.19~150300.3.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-diameter-src", rpm:"erlang-diameter-src~23.3.4.19~150300.3.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-doc", rpm:"erlang-doc~23.3.4.19~150300.3.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-epmd", rpm:"erlang-epmd~23.3.4.19~150300.3.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-et", rpm:"erlang-et~23.3.4.19~150300.3.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-et-src", rpm:"erlang-et-src~23.3.4.19~150300.3.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-jinterface", rpm:"erlang-jinterface~23.3.4.19~150300.3.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-jinterface-src", rpm:"erlang-jinterface-src~23.3.4.19~150300.3.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-observer", rpm:"erlang-observer~23.3.4.19~150300.3.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-observer-src", rpm:"erlang-observer-src~23.3.4.19~150300.3.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-reltool", rpm:"erlang-reltool~23.3.4.19~150300.3.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-reltool-src", rpm:"erlang-reltool-src~23.3.4.19~150300.3.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-src", rpm:"erlang-src~23.3.4.19~150300.3.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-wx", rpm:"erlang-wx~23.3.4.19~150300.3.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-wx-src", rpm:"erlang-wx-src~23.3.4.19~150300.3.29.1", rls:"openSUSELeap15.6"))) {
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

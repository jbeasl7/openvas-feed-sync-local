# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.1051.1");
  script_cve_id("CVE-2025-26618");
  script_tag(name:"creation_date", value:"2025-03-31 04:06:52 +0000 (Mon, 31 Mar 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:1051-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1051-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251051-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237467");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-March/020619.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'erlang26' package(s) announced via the SUSE-SU-2025:1051-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for erlang26 fixes the following issues:

- CVE-2025-26618: Fixed incorrect verification of SSH SFTP packet size in Erlang OTP (bsc#1237467)");

  script_tag(name:"affected", value:"'erlang26' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"erlang26", rpm:"erlang26~26.2.1~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang26-debugger", rpm:"erlang26-debugger~26.2.1~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang26-debugger-src", rpm:"erlang26-debugger-src~26.2.1~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang26-dialyzer", rpm:"erlang26-dialyzer~26.2.1~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang26-dialyzer-src", rpm:"erlang26-dialyzer-src~26.2.1~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang26-diameter", rpm:"erlang26-diameter~26.2.1~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang26-diameter-src", rpm:"erlang26-diameter-src~26.2.1~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang26-doc", rpm:"erlang26-doc~26.2.1~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang26-epmd", rpm:"erlang26-epmd~26.2.1~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang26-et", rpm:"erlang26-et~26.2.1~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang26-et-src", rpm:"erlang26-et-src~26.2.1~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang26-jinterface", rpm:"erlang26-jinterface~26.2.1~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang26-jinterface-src", rpm:"erlang26-jinterface-src~26.2.1~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang26-observer", rpm:"erlang26-observer~26.2.1~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang26-observer-src", rpm:"erlang26-observer-src~26.2.1~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang26-reltool", rpm:"erlang26-reltool~26.2.1~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang26-reltool-src", rpm:"erlang26-reltool-src~26.2.1~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang26-src", rpm:"erlang26-src~26.2.1~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang26-wx", rpm:"erlang26-wx~26.2.1~150300.7.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang26-wx-src", rpm:"erlang26-wx-src~26.2.1~150300.7.8.1", rls:"openSUSELeap15.6"))) {
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

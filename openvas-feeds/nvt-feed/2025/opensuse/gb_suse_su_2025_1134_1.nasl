# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.1134.1");
  script_tag(name:"creation_date", value:"2025-04-07 04:06:30 +0000 (Mon, 07 Apr 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:1134-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1134-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251134-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234452");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-April/038904.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apparmor' package(s) announced via the SUSE-SU-2025:1134-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apparmor fixes the following issue:

- Allow dovecot-auth to execute unix check password from /sbin, not only from /usr/bin (bsc#1234452).");

  script_tag(name:"affected", value:"'apparmor' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_apparmor", rpm:"apache2-mod_apparmor~3.1.7~150600.5.3.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apparmor-abstractions", rpm:"apparmor-abstractions~3.1.7~150600.5.3.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apparmor-docs", rpm:"apparmor-docs~3.1.7~150600.5.3.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apparmor-parser", rpm:"apparmor-parser~3.1.7~150600.5.3.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apparmor-parser-lang", rpm:"apparmor-parser-lang~3.1.7~150600.5.3.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apparmor-profiles", rpm:"apparmor-profiles~3.1.7~150600.5.3.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apparmor-utils", rpm:"apparmor-utils~3.1.7~150600.5.3.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apparmor-utils-lang", rpm:"apparmor-utils-lang~3.1.7~150600.5.3.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapparmor-devel", rpm:"libapparmor-devel~3.1.7~150600.5.3.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapparmor1", rpm:"libapparmor1~3.1.7~150600.5.3.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapparmor1-32bit", rpm:"libapparmor1-32bit~3.1.7~150600.5.3.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam_apparmor", rpm:"pam_apparmor~3.1.7~150600.5.3.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam_apparmor-32bit", rpm:"pam_apparmor-32bit~3.1.7~150600.5.3.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-apparmor", rpm:"perl-apparmor~3.1.7~150600.5.3.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-apparmor", rpm:"python3-apparmor~3.1.7~150600.5.3.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-apparmor", rpm:"ruby-apparmor~3.1.7~150600.5.3.2", rls:"openSUSELeap15.6"))) {
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

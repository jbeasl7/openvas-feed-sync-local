# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856166");
  script_cve_id("CVE-2024-36048");
  script_tag(name:"creation_date", value:"2024-05-28 01:00:24 +0000 (Tue, 28 May 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0143-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0143-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/5URUTAIVXSJ76TICREGEFK7QSJ244FKX/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224782");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libqt5-qtnetworkauth' package(s) announced via the openSUSE-SU-2024:0143-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libqt5-qtnetworkauth fixes the following issues:

- CVE-2024-36048: Fixed data race and poor seeding in generateRandomString() (boo#1224782).");

  script_tag(name:"affected", value:"'libqt5-qtnetworkauth' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libQt5NetworkAuth5-32bit", rpm:"libQt5NetworkAuth5-32bit~5.15.2+kde2~bp155.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5NetworkAuth5", rpm:"libQt5NetworkAuth5~5.15.2+kde2~bp155.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5NetworkAuth5-64bit", rpm:"libQt5NetworkAuth5-64bit~5.15.2+kde2~bp155.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtnetworkauth-devel-32bit", rpm:"libqt5-qtnetworkauth-devel-32bit~5.15.2+kde2~bp155.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtnetworkauth-devel", rpm:"libqt5-qtnetworkauth-devel~5.15.2+kde2~bp155.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtnetworkauth-devel-64bit", rpm:"libqt5-qtnetworkauth-devel-64bit~5.15.2+kde2~bp155.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtnetworkauth-examples", rpm:"libqt5-qtnetworkauth-examples~5.15.2+kde2~bp155.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtnetworkauth-private-headers-devel", rpm:"libqt5-qtnetworkauth-private-headers-devel~5.15.2+kde2~bp155.3.3.1", rls:"openSUSELeap15.5"))) {
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

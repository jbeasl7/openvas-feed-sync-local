# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.649798102210210221");
  script_cve_id("CVE-2025-8194");
  script_tag(name:"creation_date", value:"2025-08-12 04:09:52 +0000 (Tue, 12 Aug 2025)");
  script_version("2025-08-13T05:40:47+0000");
  script_tag(name:"last_modification", value:"2025-08-13 05:40:47 +0000 (Wed, 13 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-64abf2ff21)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-64abf2ff21");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-64abf2ff21");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2384063");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2384074");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-python3' package(s) announced via the FEDORA-2025-64abf2ff21 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Backport fix for CVE-2025-8194.");

  script_tag(name:"affected", value:"'mingw-python3' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"mingw-python3", rpm:"mingw-python3~3.11.13~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-python3", rpm:"mingw32-python3~3.11.13~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-python3-debuginfo", rpm:"mingw32-python3-debuginfo~3.11.13~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-python3-idle", rpm:"mingw32-python3-idle~3.11.13~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-python3-test", rpm:"mingw32-python3-test~3.11.13~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-python3-tkinter", rpm:"mingw32-python3-tkinter~3.11.13~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-python3", rpm:"mingw64-python3~3.11.13~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-python3-debuginfo", rpm:"mingw64-python3-debuginfo~3.11.13~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-python3-idle", rpm:"mingw64-python3-idle~3.11.13~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-python3-test", rpm:"mingw64-python3-test~3.11.13~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-python3-tkinter", rpm:"mingw64-python3-tkinter~3.11.13~4.fc41", rls:"FC41"))) {
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

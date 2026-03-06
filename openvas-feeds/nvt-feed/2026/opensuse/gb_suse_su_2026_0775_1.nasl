# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0775.1");
  script_cve_id("CVE-2026-2604");
  script_tag(name:"creation_date", value:"2026-03-05 04:35:07 +0000 (Thu, 05 Mar 2026)");
  script_version("2026-03-05T05:55:06+0000");
  script_tag(name:"last_modification", value:"2026-03-05 05:55:06 +0000 (Thu, 05 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0775-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0775-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260775-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258307");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024543.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'evolution-data-server' package(s) announced via the SUSE-SU-2026:0775-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for evolution-data-server fixes the following issue:

- CVE-2026-2604: arbitrary file deletion via inconsistent URI handling (bsc#1258307).");

  script_tag(name:"affected", value:"'evolution-data-server' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"evolution-data-server", rpm:"evolution-data-server~3.50.3~150600.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-data-server-devel", rpm:"evolution-data-server-devel~3.50.3~150600.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-data-server-lang", rpm:"evolution-data-server-lang~3.50.3~150600.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcamel-1_2-64", rpm:"libcamel-1_2-64~3.50.3~150600.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebackend-1_2-11", rpm:"libebackend-1_2-11~3.50.3~150600.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebook-1_2-21", rpm:"libebook-1_2-21~3.50.3~150600.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebook-contacts-1_2-4", rpm:"libebook-contacts-1_2-4~3.50.3~150600.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecal-2_0-2", rpm:"libecal-2_0-2~3.50.3~150600.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedata-book-1_2-27", rpm:"libedata-book-1_2-27~3.50.3~150600.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedata-cal-2_0-2", rpm:"libedata-cal-2_0-2~3.50.3~150600.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedataserver-1_2-27", rpm:"libedataserver-1_2-27~3.50.3~150600.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedataserverui-1_2-4", rpm:"libedataserverui-1_2-4~3.50.3~150600.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libedataserverui4-1_0-0", rpm:"libedataserverui4-1_0-0~3.50.3~150600.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Camel-1_2", rpm:"typelib-1_0-Camel-1_2~3.50.3~150600.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-EBackend-1_2", rpm:"typelib-1_0-EBackend-1_2~3.50.3~150600.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-EBook-1_2", rpm:"typelib-1_0-EBook-1_2~3.50.3~150600.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-EBookContacts-1_2", rpm:"typelib-1_0-EBookContacts-1_2~3.50.3~150600.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-ECal-2_0", rpm:"typelib-1_0-ECal-2_0~3.50.3~150600.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-EDataBook-1_2", rpm:"typelib-1_0-EDataBook-1_2~3.50.3~150600.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-EDataCal-2_0", rpm:"typelib-1_0-EDataCal-2_0~3.50.3~150600.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-EDataServer-1_2", rpm:"typelib-1_0-EDataServer-1_2~3.50.3~150600.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-EDataServerUI-1_2", rpm:"typelib-1_0-EDataServerUI-1_2~3.50.3~150600.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-EDataServerUI4-1_0", rpm:"typelib-1_0-EDataServerUI4-1_0~3.50.3~150600.3.9.1", rls:"openSUSELeap15.6"))) {
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

# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884882");
  script_cve_id("CVE-2023-39742");
  script_tag(name:"creation_date", value:"2023-10-01 01:18:12 +0000 (Sun, 01 Oct 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-28 13:59:41 +0000 (Mon, 28 Aug 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-6ce92a5bdc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-6ce92a5bdc");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-6ce92a5bdc");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238790");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'giflib' package(s) announced via the FEDORA-2023-6ce92a5bdc advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Add patch for CVE-2023.39742.");

  script_tag(name:"affected", value:"'giflib' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"giflib", rpm:"giflib~5.2.1~17.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"giflib-debuginfo", rpm:"giflib-debuginfo~5.2.1~17.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"giflib-debugsource", rpm:"giflib-debugsource~5.2.1~17.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"giflib-devel", rpm:"giflib-devel~5.2.1~17.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"giflib-utils", rpm:"giflib-utils~5.2.1~17.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"giflib-utils-debuginfo", rpm:"giflib-utils-debuginfo~5.2.1~17.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-giflib", rpm:"mingw32-giflib~5.2.1~17.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-giflib-debuginfo", rpm:"mingw32-giflib-debuginfo~5.2.1~17.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-giflib-tools", rpm:"mingw32-giflib-tools~5.2.1~17.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-giflib", rpm:"mingw64-giflib~5.2.1~17.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-giflib-debuginfo", rpm:"mingw64-giflib-debuginfo~5.2.1~17.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-giflib-tools", rpm:"mingw64-giflib-tools~5.2.1~17.fc39", rls:"FC39"))) {
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

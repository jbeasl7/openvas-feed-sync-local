# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.9102517977495");
  script_cve_id("CVE-2026-25990");
  script_tag(name:"creation_date", value:"2026-02-18 04:41:15 +0000 (Wed, 18 Feb 2026)");
  script_version("2026-02-18T05:57:21+0000");
  script_tag(name:"last_modification", value:"2026-02-18 05:57:21 +0000 (Wed, 18 Feb 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-13 21:32:55 +0000 (Fri, 13 Feb 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-9f517a7495)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-9f517a7495");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-9f517a7495");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2439192");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2439196");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-pillow' package(s) announced via the FEDORA-2026-9f517a7495 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Backport fix for CVE-2026-25990.");

  script_tag(name:"affected", value:"'python-pillow' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"mingw32-python-pillow-debuginfo", rpm:"mingw32-python-pillow-debuginfo~11.3.0~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-python3-pillow", rpm:"mingw32-python3-pillow~11.3.0~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-python-pillow-debuginfo", rpm:"mingw64-python-pillow-debuginfo~11.3.0~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-python3-pillow", rpm:"mingw64-python3-pillow~11.3.0~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pillow", rpm:"python-pillow~11.3.0~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pillow-debuginfo", rpm:"python-pillow-debuginfo~11.3.0~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pillow-debugsource", rpm:"python-pillow-debugsource~11.3.0~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow", rpm:"python3-pillow~11.3.0~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow-debuginfo", rpm:"python3-pillow-debuginfo~11.3.0~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow-devel", rpm:"python3-pillow-devel~11.3.0~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow-qt", rpm:"python3-pillow-qt~11.3.0~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow-tk", rpm:"python3-pillow-tk~11.3.0~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow-tk-debuginfo", rpm:"python3-pillow-tk-debuginfo~11.3.0~7.fc43", rls:"FC43"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.10129931009810098101101");
  script_cve_id("CVE-2024-56378", "CVE-2025-32364", "CVE-2025-32365");
  script_tag(name:"creation_date", value:"2025-08-04 04:27:09 +0000 (Mon, 04 Aug 2025)");
  script_version("2025-08-04T05:47:09+0000");
  script_tag(name:"last_modification", value:"2025-08-04 05:47:09 +0000 (Mon, 04 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-e2c3dbdbee)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-e2c3dbdbee");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-e2c3dbdbee");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2333794");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2333815");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2357656");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2357657");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2357815");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2357819");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler' package(s) announced via the FEDORA-2025-e2c3dbdbee advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes these CVEs:
 CVE-2025-32364
 CVE-2025-32365
 CVE-2024-56378");

  script_tag(name:"affected", value:"'poppler' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"poppler", rpm:"poppler~25.02.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-cpp", rpm:"poppler-cpp~25.02.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-cpp-debuginfo", rpm:"poppler-cpp-debuginfo~25.02.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-cpp-devel", rpm:"poppler-cpp-devel~25.02.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-debuginfo", rpm:"poppler-debuginfo~25.02.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-debugsource", rpm:"poppler-debugsource~25.02.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-devel", rpm:"poppler-devel~25.02.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-glib", rpm:"poppler-glib~25.02.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-glib-debuginfo", rpm:"poppler-glib-debuginfo~25.02.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-glib-devel", rpm:"poppler-glib-devel~25.02.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-glib-doc", rpm:"poppler-glib-doc~25.02.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-qt5", rpm:"poppler-qt5~25.02.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-qt5-debuginfo", rpm:"poppler-qt5-debuginfo~25.02.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-qt5-devel", rpm:"poppler-qt5-devel~25.02.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-qt6", rpm:"poppler-qt6~25.02.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-qt6-debuginfo", rpm:"poppler-qt6-debuginfo~25.02.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-qt6-devel", rpm:"poppler-qt6-devel~25.02.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-utils", rpm:"poppler-utils~25.02.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-utils-debuginfo", rpm:"poppler-utils-debuginfo~25.02.0~2.fc42", rls:"FC42"))) {
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

# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.99898341810291");
  script_cve_id("CVE-2025-11468", "CVE-2025-15282", "CVE-2026-0672", "CVE-2026-0865", "CVE-2026-1299");
  script_tag(name:"creation_date", value:"2026-02-18 04:41:15 +0000 (Wed, 18 Feb 2026)");
  script_version("2026-02-18T05:57:21+0000");
  script_tag(name:"last_modification", value:"2026-02-18 05:57:21 +0000 (Wed, 18 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-c8b3418f91)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-c8b3418f91");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-c8b3418f91");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431752");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431762");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431781");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431790");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431806");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431817");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431818");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431839");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2433814");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2433824");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-python3' package(s) announced via the FEDORA-2026-c8b3418f91 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Backport fixes for CVE-2025-11468, CVE-2026-0672, CVE-2026-0865, CVE-2025-15282, CVE-2026-1299");

  script_tag(name:"affected", value:"'mingw-python3' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"mingw-python3", rpm:"mingw-python3~3.11.14~7.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-python3", rpm:"mingw32-python3~3.11.14~7.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-python3-debuginfo", rpm:"mingw32-python3-debuginfo~3.11.14~7.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-python3-idle", rpm:"mingw32-python3-idle~3.11.14~7.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-python3-test", rpm:"mingw32-python3-test~3.11.14~7.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-python3-tkinter", rpm:"mingw32-python3-tkinter~3.11.14~7.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-python3", rpm:"mingw64-python3~3.11.14~7.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-python3-debuginfo", rpm:"mingw64-python3-debuginfo~3.11.14~7.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-python3-idle", rpm:"mingw64-python3-idle~3.11.14~7.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-python3-test", rpm:"mingw64-python3-test~3.11.14~7.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-python3-tkinter", rpm:"mingw64-python3-tkinter~3.11.14~7.fc42", rls:"FC42"))) {
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

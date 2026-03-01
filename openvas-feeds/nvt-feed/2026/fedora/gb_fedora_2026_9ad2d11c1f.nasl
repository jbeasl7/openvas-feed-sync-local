# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.997100210011991102");
  script_cve_id("CVE-2025-11468", "CVE-2025-15282", "CVE-2026-0672", "CVE-2026-0865", "CVE-2026-1299");
  script_tag(name:"creation_date", value:"2026-02-20 04:37:04 +0000 (Fri, 20 Feb 2026)");
  script_version("2026-02-20T05:55:45+0000");
  script_tag(name:"last_modification", value:"2026-02-20 05:55:45 +0000 (Fri, 20 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-9ad2d11c1f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-9ad2d11c1f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-9ad2d11c1f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431785");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431794");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431800");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431816");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2433819");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.14' package(s) announced via the FEDORA-2026-9ad2d11c1f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New version of the Python interpreter also bringing security fixes.");

  script_tag(name:"affected", value:"'python3.14' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3.14", rpm:"python3.14~3.14.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-debug", rpm:"python3.14-debug~3.14.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-debuginfo", rpm:"python3.14-debuginfo~3.14.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-debugsource", rpm:"python3.14-debugsource~3.14.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-devel", rpm:"python3.14-devel~3.14.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-freethreading", rpm:"python3.14-freethreading~3.14.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-freethreading-debug", rpm:"python3.14-freethreading-debug~3.14.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-freethreading-devel", rpm:"python3.14-freethreading-devel~3.14.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-freethreading-idle", rpm:"python3.14-freethreading-idle~3.14.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-freethreading-libs", rpm:"python3.14-freethreading-libs~3.14.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-freethreading-test", rpm:"python3.14-freethreading-test~3.14.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-freethreading-tkinter", rpm:"python3.14-freethreading-tkinter~3.14.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-idle", rpm:"python3.14-idle~3.14.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-libs", rpm:"python3.14-libs~3.14.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-test", rpm:"python3.14-test~3.14.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-tkinter", rpm:"python3.14-tkinter~3.14.3~1.fc42", rls:"FC42"))) {
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

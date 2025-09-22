# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.621021017461011000");
  script_cve_id("CVE-2025-8194");
  script_tag(name:"creation_date", value:"2025-08-26 04:05:26 +0000 (Tue, 26 Aug 2025)");
  script_version("2025-08-27T05:39:13+0000");
  script_tag(name:"last_modification", value:"2025-08-27 05:39:13 +0000 (Wed, 27 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-62fe746ed0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-62fe746ed0");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-62fe746ed0");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2384068");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/137583");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-8194");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3-docs, python3.13' package(s) announced via the FEDORA-2025-62fe746ed0 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Python 3.13.7 is the seventh maintenance release of 3.13.

3.13.7 is an expedited release to fix a significant issue with the 3.13.6 release:

- [gh-137583]([link moved to references]): Regression in ssl module between 3.13.5 and 3.13.6: reading from a TLS-encrypted connection blocks

A few other bug fixes (which would otherwise have waited until the next release) are also included.

----

3.13.6 is the sixth maintenance release of 3.13, containing around 200 bugfixes, build improvements and documentation changes since 3.13.5.

----

This update contains fix for [link moved to references]");

  script_tag(name:"affected", value:"'python3-docs, python3.13' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-unversioned-command", rpm:"python-unversioned-command~3.13.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.13.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-debug", rpm:"python3-debug~3.13.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-devel", rpm:"python3-devel~3.13.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-docs", rpm:"python3-docs~3.13.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-idle", rpm:"python3-idle~3.13.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libs", rpm:"python3-libs~3.13.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-test", rpm:"python3-test~3.13.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tkinter", rpm:"python3-tkinter~3.13.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.13", rpm:"python3.13~3.13.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.13-debuginfo", rpm:"python3.13-debuginfo~3.13.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.13-debugsource", rpm:"python3.13-debugsource~3.13.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.13-freethreading", rpm:"python3.13-freethreading~3.13.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.13-freethreading-debug", rpm:"python3.13-freethreading-debug~3.13.7~1.fc41", rls:"FC41"))) {
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

# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.2799101708600");
  script_cve_id("CVE-2025-11468", "CVE-2025-15282", "CVE-2026-0672", "CVE-2026-0865", "CVE-2026-1299");
  script_tag(name:"creation_date", value:"2026-02-26 04:38:18 +0000 (Thu, 26 Feb 2026)");
  script_version("2026-02-26T05:57:26+0000");
  script_tag(name:"last_modification", value:"2026-02-26 05:57:26 +0000 (Thu, 26 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-27ce708600)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-27ce708600");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-27ce708600");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2424574");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431825");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431837");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431838");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431851");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2433829");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2436933");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds-base, python3-docs, python3.14' package(s) announced via the FEDORA-2026-27ce708600 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- New minor version of the Python interpreter, bringing also security fixes.
- 389-ds-base: Fix system index configuration issues
- 389-ds-base: Fix AttributeError: 'CustomHelpFormatter' object has no attribute '_format_actions_usage'");

  script_tag(name:"affected", value:"'389-ds-base, python3-docs, python3.14' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~3.1.4~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-debuginfo", rpm:"389-ds-base-debuginfo~3.1.4~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-debugsource", rpm:"389-ds-base-debugsource~3.1.4~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-devel", rpm:"389-ds-base-devel~3.1.4~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~3.1.4~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-libs-debuginfo", rpm:"389-ds-base-libs-debuginfo~3.1.4~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-robdb-libs", rpm:"389-ds-base-robdb-libs~3.1.4~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-robdb-libs-debuginfo", rpm:"389-ds-base-robdb-libs-debuginfo~3.1.4~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-snmp", rpm:"389-ds-base-snmp~3.1.4~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-snmp-debuginfo", rpm:"389-ds-base-snmp-debuginfo~3.1.4~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-389-ds", rpm:"cockpit-389-ds~3.1.4~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-unversioned-command", rpm:"python-unversioned-command~3.14.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.14.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-debug", rpm:"python3-debug~3.14.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-devel", rpm:"python3-devel~3.14.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-docs", rpm:"python3-docs~3.14.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-idle", rpm:"python3-idle~3.14.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-lib389", rpm:"python3-lib389~3.1.4~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libs", rpm:"python3-libs~3.14.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-test", rpm:"python3-test~3.14.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tkinter", rpm:"python3-tkinter~3.14.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14", rpm:"python3.14~3.14.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-debuginfo", rpm:"python3.14-debuginfo~3.14.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-debugsource", rpm:"python3.14-debugsource~3.14.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-freethreading", rpm:"python3.14-freethreading~3.14.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-freethreading-debug", rpm:"python3.14-freethreading-debug~3.14.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-freethreading-devel", rpm:"python3.14-freethreading-devel~3.14.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-freethreading-idle", rpm:"python3.14-freethreading-idle~3.14.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-freethreading-libs", rpm:"python3.14-freethreading-libs~3.14.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-freethreading-test", rpm:"python3.14-freethreading-test~3.14.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-freethreading-tkinter", rpm:"python3.14-freethreading-tkinter~3.14.3~1.fc43", rls:"FC43"))) {
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

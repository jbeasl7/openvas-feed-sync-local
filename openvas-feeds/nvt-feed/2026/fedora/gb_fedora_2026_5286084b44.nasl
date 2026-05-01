# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.52860849844");
  script_cve_id("CVE-2026-34078", "CVE-2026-34079");
  script_tag(name:"creation_date", value:"2026-04-14 05:00:06 +0000 (Tue, 14 Apr 2026)");
  script_version("2026-04-14T06:16:47+0000");
  script_tag(name:"last_modification", value:"2026-04-14 06:16:47 +0000 (Tue, 14 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-5286084b44)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-5286084b44");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-5286084b44");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2456384");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2456395");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flatpak' package(s) announced via the FEDORA-2026-5286084b44 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 1.16.6

Fixes for CVE-2026-34078, CVE-2026-34079, GHSA-2fxp-43j9-pwvc and GHSA-89xm-3m96-w3jg");

  script_tag(name:"affected", value:"'flatpak' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"flatpak", rpm:"flatpak~1.16.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-debuginfo", rpm:"flatpak-debuginfo~1.16.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-debugsource", rpm:"flatpak-debugsource~1.16.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-devel", rpm:"flatpak-devel~1.16.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-libs", rpm:"flatpak-libs~1.16.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-libs-debuginfo", rpm:"flatpak-libs-debuginfo~1.16.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-selinux", rpm:"flatpak-selinux~1.16.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-session-helper", rpm:"flatpak-session-helper~1.16.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-session-helper-debuginfo", rpm:"flatpak-session-helper-debuginfo~1.16.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-tests", rpm:"flatpak-tests~1.16.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-tests-debuginfo", rpm:"flatpak-tests-debuginfo~1.16.6~1.fc43", rls:"FC43"))) {
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

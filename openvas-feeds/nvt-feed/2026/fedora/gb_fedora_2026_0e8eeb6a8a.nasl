# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.0101810110198697897");
  script_cve_id("CVE-2026-4105");
  script_tag(name:"creation_date", value:"2026-03-16 04:56:17 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-16T06:13:25+0000");
  script_tag(name:"last_modification", value:"2026-03-16 06:13:25 +0000 (Mon, 16 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-13 19:55:13 +0000 (Fri, 13 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-0e8eeb6a8a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-0e8eeb6a8a");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-0e8eeb6a8a");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2447267");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd' package(s) announced via the FEDORA-2026-0e8eeb6a8a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- A bunch of bugfixes
- More sanitization for invalid values received from hardware and firmware");

  script_tag(name:"affected", value:"'systemd' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-boot-unsigned", rpm:"systemd-boot-unsigned~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-container", rpm:"systemd-container~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-container-debuginfo", rpm:"systemd-container-debuginfo~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debuginfo", rpm:"systemd-debuginfo~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debugsource", rpm:"systemd-debugsource~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-devel", rpm:"systemd-devel~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-journal-remote", rpm:"systemd-journal-remote~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-journal-remote-debuginfo", rpm:"systemd-journal-remote-debuginfo~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-libs", rpm:"systemd-libs~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-libs-debuginfo", rpm:"systemd-libs-debuginfo~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-networkd", rpm:"systemd-networkd~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-networkd-debuginfo", rpm:"systemd-networkd-debuginfo~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-networkd-defaults", rpm:"systemd-networkd-defaults~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-oomd-defaults", rpm:"systemd-oomd-defaults~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-pam", rpm:"systemd-pam~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-pam-debuginfo", rpm:"systemd-pam-debuginfo~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-resolved", rpm:"systemd-resolved~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-resolved-debuginfo", rpm:"systemd-resolved-debuginfo~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-rpm-macros", rpm:"systemd-rpm-macros~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-shared", rpm:"systemd-shared~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-shared-debuginfo", rpm:"systemd-shared-debuginfo~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-standalone-repart", rpm:"systemd-standalone-repart~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-standalone-repart-debuginfo", rpm:"systemd-standalone-repart-debuginfo~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-standalone-shutdown", rpm:"systemd-standalone-shutdown~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-standalone-shutdown-debuginfo", rpm:"systemd-standalone-shutdown-debuginfo~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-standalone-sysusers", rpm:"systemd-standalone-sysusers~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-standalone-sysusers-debuginfo", rpm:"systemd-standalone-sysusers-debuginfo~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-standalone-tmpfiles", rpm:"systemd-standalone-tmpfiles~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-standalone-tmpfiles-debuginfo", rpm:"systemd-standalone-tmpfiles-debuginfo~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysusers", rpm:"systemd-sysusers~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysusers-debuginfo", rpm:"systemd-sysusers-debuginfo~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-tests", rpm:"systemd-tests~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-tests-debuginfo", rpm:"systemd-tests-debuginfo~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-udev", rpm:"systemd-udev~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-udev-debuginfo", rpm:"systemd-udev-debuginfo~258.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-ukify", rpm:"systemd-ukify~258.7~1.fc43", rls:"FC43"))) {
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

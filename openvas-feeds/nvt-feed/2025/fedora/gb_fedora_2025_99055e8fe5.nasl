# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.9905510181021015");
  script_cve_id("CVE-2025-4598");
  script_tag(name:"creation_date", value:"2025-06-02 04:11:15 +0000 (Mon, 02 Jun 2025)");
  script_version("2025-06-02T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-06-02 05:40:56 +0000 (Mon, 02 Jun 2025)");
  script_tag(name:"cvss_base", value:"3.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-30 14:15:23 +0000 (Fri, 30 May 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-99055e8fe5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-99055e8fe5");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-99055e8fe5");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2369247");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd' package(s) announced via the FEDORA-2025-99055e8fe5 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Fix for local information disclosure in systemd-coredump (CVE-2025-4598)
- Fixes for systemd itself, run0, systemd-networkd, 'secure' pager, man pages, shell completions, sd-boot, sd-varlink
- Hardware database update");

  script_tag(name:"affected", value:"'systemd' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-boot-unsigned", rpm:"systemd-boot-unsigned~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-container", rpm:"systemd-container~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-container-debuginfo", rpm:"systemd-container-debuginfo~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debuginfo", rpm:"systemd-debuginfo~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debugsource", rpm:"systemd-debugsource~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-devel", rpm:"systemd-devel~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-journal-remote", rpm:"systemd-journal-remote~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-journal-remote-debuginfo", rpm:"systemd-journal-remote-debuginfo~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-libs", rpm:"systemd-libs~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-libs-debuginfo", rpm:"systemd-libs-debuginfo~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-networkd", rpm:"systemd-networkd~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-networkd-debuginfo", rpm:"systemd-networkd-debuginfo~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-networkd-defaults", rpm:"systemd-networkd-defaults~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-oomd-defaults", rpm:"systemd-oomd-defaults~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-pam", rpm:"systemd-pam~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-pam-debuginfo", rpm:"systemd-pam-debuginfo~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-resolved", rpm:"systemd-resolved~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-resolved-debuginfo", rpm:"systemd-resolved-debuginfo~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-rpm-macros", rpm:"systemd-rpm-macros~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-shared", rpm:"systemd-shared~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-shared-debuginfo", rpm:"systemd-shared-debuginfo~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-standalone-repart", rpm:"systemd-standalone-repart~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-standalone-repart-debuginfo", rpm:"systemd-standalone-repart-debuginfo~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-standalone-shutdown", rpm:"systemd-standalone-shutdown~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-standalone-shutdown-debuginfo", rpm:"systemd-standalone-shutdown-debuginfo~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-standalone-sysusers", rpm:"systemd-standalone-sysusers~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-standalone-sysusers-debuginfo", rpm:"systemd-standalone-sysusers-debuginfo~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-standalone-tmpfiles", rpm:"systemd-standalone-tmpfiles~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-standalone-tmpfiles-debuginfo", rpm:"systemd-standalone-tmpfiles-debuginfo~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysusers", rpm:"systemd-sysusers~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysusers-debuginfo", rpm:"systemd-sysusers-debuginfo~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-tests", rpm:"systemd-tests~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-tests-debuginfo", rpm:"systemd-tests-debuginfo~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-udev", rpm:"systemd-udev~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-udev-debuginfo", rpm:"systemd-udev-debuginfo~257.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-ukify", rpm:"systemd-ukify~257.6~1.fc42", rls:"FC42"))) {
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

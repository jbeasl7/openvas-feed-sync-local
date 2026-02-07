# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.841001011534981");
  script_cve_id("CVE-2025-13465");
  script_tag(name:"creation_date", value:"2026-02-06 04:37:17 +0000 (Fri, 06 Feb 2026)");
  script_version("2026-02-06T05:56:14+0000");
  script_tag(name:"last_modification", value:"2026-02-06 05:56:14 +0000 (Fri, 06 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-84de1534b1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-84de1534b1");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-84de1534b1");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2432984");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-13465");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openqa' package(s) announced via the FEDORA-2026-84de1534b1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update bumps the bundled lodash to 4.17.23 to ensure openQA is protected against [CVE-2025-13465]([link moved to references]). It likely was not vulnerable in any case, though, as I don't believe the vulnerable codepaths were exposed by openQA's use of lodash.");

  script_tag(name:"affected", value:"'openqa' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"openqa", rpm:"openqa~5^20250711git28a0214~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-bootstrap", rpm:"openqa-bootstrap~5^20250711git28a0214~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-client", rpm:"openqa-client~5^20250711git28a0214~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-common", rpm:"openqa-common~5^20250711git28a0214~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-devel", rpm:"openqa-devel~5^20250711git28a0214~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-doc", rpm:"openqa-doc~5^20250711git28a0214~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-httpd", rpm:"openqa-httpd~5^20250711git28a0214~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-local-db", rpm:"openqa-local-db~5^20250711git28a0214~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-munin", rpm:"openqa-munin~5^20250711git28a0214~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-plugin-fedora-messaging", rpm:"openqa-plugin-fedora-messaging~5^20250711git28a0214~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-plugin-fedoraupdaterestart", rpm:"openqa-plugin-fedoraupdaterestart~5^20250711git28a0214~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-python-scripts", rpm:"openqa-python-scripts~5^20250711git28a0214~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-single-instance", rpm:"openqa-single-instance~5^20250711git28a0214~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-single-instance-nginx", rpm:"openqa-single-instance-nginx~5^20250711git28a0214~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-worker", rpm:"openqa-worker~5^20250711git28a0214~4.fc42", rls:"FC42"))) {
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

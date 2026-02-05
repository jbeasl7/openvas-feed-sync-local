# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.9798100210021006099");
  script_cve_id("CVE-2025-13465");
  script_tag(name:"creation_date", value:"2026-02-04 04:35:12 +0000 (Wed, 04 Feb 2026)");
  script_version("2026-02-04T05:55:03+0000");
  script_tag(name:"last_modification", value:"2026-02-04 05:55:03 +0000 (Wed, 04 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-abd2d2d60c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-abd2d2d60c");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-abd2d2d60c");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2433034");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openqa, os-autoinst' package(s) announced via the FEDORA-2026-abd2d2d60c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides new upstream snapshots of openQA and os-autoinst, with various fixes and enhancements. Please see upstream changelogs for details. They also address a CVE by updating a bundled javascript library, though we're fairly sure openQA didn't actually expose the vulnerability anyway.");

  script_tag(name:"affected", value:"'openqa, os-autoinst' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"openqa", rpm:"openqa~5^20260126git19189f0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-bootstrap", rpm:"openqa-bootstrap~5^20260126git19189f0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-client", rpm:"openqa-client~5^20260126git19189f0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-common", rpm:"openqa-common~5^20260126git19189f0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-devel", rpm:"openqa-devel~5^20260126git19189f0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-doc", rpm:"openqa-doc~5^20260126git19189f0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-httpd", rpm:"openqa-httpd~5^20260126git19189f0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-local-db", rpm:"openqa-local-db~5^20260126git19189f0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-munin", rpm:"openqa-munin~5^20260126git19189f0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-plugin-fedora-messaging", rpm:"openqa-plugin-fedora-messaging~5^20260126git19189f0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-plugin-fedoraupdaterestart", rpm:"openqa-plugin-fedoraupdaterestart~5^20260126git19189f0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-python-scripts", rpm:"openqa-python-scripts~5^20260126git19189f0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-single-instance", rpm:"openqa-single-instance~5^20260126git19189f0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-single-instance-nginx", rpm:"openqa-single-instance-nginx~5^20260126git19189f0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openqa-worker", rpm:"openqa-worker~5^20260126git19189f0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"os-autoinst", rpm:"os-autoinst~5^20260123git72cabd0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"os-autoinst-debuginfo", rpm:"os-autoinst-debuginfo~5^20260123git72cabd0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"os-autoinst-debugsource", rpm:"os-autoinst-debugsource~5^20260123git72cabd0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"os-autoinst-devel", rpm:"os-autoinst-devel~5^20260123git72cabd0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"os-autoinst-openvswitch", rpm:"os-autoinst-openvswitch~5^20260123git72cabd0~1.fc43", rls:"FC43"))) {
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

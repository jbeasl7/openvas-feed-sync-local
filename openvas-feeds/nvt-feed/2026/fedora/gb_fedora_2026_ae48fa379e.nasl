# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.971014810297379101");
  script_cve_id("CVE-2025-13465", "CVE-2026-25639");
  script_tag(name:"creation_date", value:"2026-03-02 04:38:01 +0000 (Mon, 02 Mar 2026)");
  script_version("2026-03-02T05:55:30+0000");
  script_tag(name:"last_modification", value:"2026-03-02 05:55:30 +0000 (Mon, 02 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-17 17:10:07 +0000 (Tue, 17 Feb 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-ae48fa379e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-ae48fa379e");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-ae48fa379e");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2432927");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2432981");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2433031");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2439004");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2439019");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2439026");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2440650");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nextcloud' package(s) announced via the FEDORA-2026-ae48fa379e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"32.0.6 release");

  script_tag(name:"affected", value:"'nextcloud' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"nextcloud", rpm:"nextcloud~32.0.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-httpd", rpm:"nextcloud-httpd~32.0.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-mysql", rpm:"nextcloud-mysql~32.0.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-nginx", rpm:"nextcloud-nginx~32.0.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-postgresql", rpm:"nextcloud-postgresql~32.0.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-sqlite", rpm:"nextcloud-sqlite~32.0.6~1.fc43", rls:"FC43"))) {
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

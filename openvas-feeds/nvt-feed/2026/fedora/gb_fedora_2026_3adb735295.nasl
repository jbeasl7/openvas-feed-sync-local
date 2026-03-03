# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.39710098735295");
  script_cve_id("CVE-2025-13473", "CVE-2025-14550", "CVE-2026-1207", "CVE-2026-1285", "CVE-2026-1287", "CVE-2026-1312");
  script_tag(name:"creation_date", value:"2026-03-02 04:38:01 +0000 (Mon, 02 Mar 2026)");
  script_version("2026-03-02T05:55:30+0000");
  script_tag(name:"last_modification", value:"2026-03-02 05:55:30 +0000 (Mon, 02 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-3adb735295)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-3adb735295");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-3adb735295");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2427483");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2436693");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2436702");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2436706");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2436707");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2436717");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django5' package(s) announced via the FEDORA-2026-3adb735295 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Fixes CVE-2025-13473: Username enumeration through timing difference in mod_wsgi authentication handler
- Fixes CVE-2025-14550: Potential denial-of-service vulnerability via repeated headers when using ASGI
- Fixes CVE-2026-1207: Potential SQL injection via raster lookups on PostGIS
- Fixes CVE-2026-1285: Potential denial-of-service vulnerability in django.utils.text.Truncator HTML methods
- Fixes CVE-2026-1287: Potential SQL injection in column aliases via control characters
- Fixes CVE-2026-1312: Potential SQL injection via QuerySet.order_by and FilteredRelation
- Fixed a bug in Django 5.2 where data exceeding max_length was silently truncated by QuerySet.bulk_create() on PostgreSQL
- Fixed a bug where management command colorized help (introduced in Python 3.14) ignored the --no-color option and the DJANGO_COLORS setting");

  script_tag(name:"affected", value:"'python-django5' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-django5", rpm:"python-django5~5.2.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-django", rpm:"python3-django~5.2.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-django-bash-completion", rpm:"python3-django-bash-completion~5.2.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-django-doc", rpm:"python3-django-doc~5.2.11~1.fc43", rls:"FC43"))) {
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

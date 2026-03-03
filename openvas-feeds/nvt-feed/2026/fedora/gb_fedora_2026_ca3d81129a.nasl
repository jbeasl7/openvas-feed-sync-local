# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.999731008112997");
  script_cve_id("CVE-2025-13473", "CVE-2025-14550", "CVE-2026-1207", "CVE-2026-1285", "CVE-2026-1287", "CVE-2026-1312");
  script_tag(name:"creation_date", value:"2026-03-02 04:38:01 +0000 (Mon, 02 Mar 2026)");
  script_version("2026-03-02T05:55:30+0000");
  script_tag(name:"last_modification", value:"2026-03-02 05:55:30 +0000 (Mon, 02 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-ca3d81129a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-ca3d81129a");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-ca3d81129a");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2436703");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2436705");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2436711");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2436720");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2436722");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django4.2' package(s) announced via the FEDORA-2026-ca3d81129a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Fixes CVE-2025-13473: Username enumeration through timing difference in mod_wsgi authentication handler
- Fixes CVE-2025-14550: Potential denial-of-service vulnerability via repeated headers when using ASGI
- Fixes CVE-2026-1207: Potential SQL injection via raster lookups on PostGIS
- Fixes CVE-2026-1285: Potential denial-of-service vulnerability in django.utils.text.Truncator HTML methods
- Fixes CVE-2026-1287: Potential SQL injection in column aliases via control characters
- Fixes CVE-2026-1312: Potential SQL injection via QuerySet.order_by and FilteredRelation");

  script_tag(name:"affected", value:"'python-django4.2' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-django4.2", rpm:"python-django4.2~4.2.28~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-django4.2-bash-completion", rpm:"python-django4.2-bash-completion~4.2.28~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-django4.2", rpm:"python3-django4.2~4.2.28~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-django4.2-doc", rpm:"python3-django4.2-doc~4.2.28~1.fc42", rls:"FC42"))) {
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

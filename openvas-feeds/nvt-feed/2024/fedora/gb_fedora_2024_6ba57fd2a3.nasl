# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887417");
  script_cve_id("CVE-2024-7347");
  script_tag(name:"creation_date", value:"2024-08-26 04:04:20 +0000 (Mon, 26 Aug 2024)");
  script_version("2025-09-08T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-09-08 05:38:50 +0000 (Mon, 08 Sep 2025)");
  script_tag(name:"cvss_base", value:"3.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-05 15:42:32 +0000 (Fri, 05 Sep 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2024-6ba57fd2a3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-6ba57fd2a3");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-6ba57fd2a3");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2305156");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nginx, nginx-mod-fancyindex, nginx-mod-modsecurity, nginx-mod-naxsi, nginx-mod-vts' package(s) announced via the FEDORA-2024-6ba57fd2a3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security: processing of a specially crafted mp4 file by the
 ngx_http_mp4_module might cause a worker process crash
 (CVE-2024-7347).
 Thanks to Nils Bars.");

  script_tag(name:"affected", value:"'nginx, nginx-mod-fancyindex, nginx-mod-modsecurity, nginx-mod-naxsi, nginx-mod-vts' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"nginx", rpm:"nginx~1.26.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-all-modules", rpm:"nginx-all-modules~1.26.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-core", rpm:"nginx-core~1.26.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-core-debuginfo", rpm:"nginx-core-debuginfo~1.26.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-debuginfo", rpm:"nginx-debuginfo~1.26.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-debugsource", rpm:"nginx-debugsource~1.26.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-filesystem", rpm:"nginx-filesystem~1.26.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-devel", rpm:"nginx-mod-devel~1.26.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-fancyindex", rpm:"nginx-mod-fancyindex~0.5.2~7.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-fancyindex-debuginfo", rpm:"nginx-mod-fancyindex-debuginfo~0.5.2~7.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-fancyindex-debugsource", rpm:"nginx-mod-fancyindex-debugsource~0.5.2~7.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-image-filter", rpm:"nginx-mod-http-image-filter~1.26.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-image-filter-debuginfo", rpm:"nginx-mod-http-image-filter-debuginfo~1.26.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-perl", rpm:"nginx-mod-http-perl~1.26.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-perl-debuginfo", rpm:"nginx-mod-http-perl-debuginfo~1.26.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-xslt-filter", rpm:"nginx-mod-http-xslt-filter~1.26.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-xslt-filter-debuginfo", rpm:"nginx-mod-http-xslt-filter-debuginfo~1.26.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-mail", rpm:"nginx-mod-mail~1.26.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-mail-debuginfo", rpm:"nginx-mod-mail-debuginfo~1.26.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-modsecurity", rpm:"nginx-mod-modsecurity~1.0.3~13.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-modsecurity-debuginfo", rpm:"nginx-mod-modsecurity-debuginfo~1.0.3~13.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-modsecurity-debugsource", rpm:"nginx-mod-modsecurity-debugsource~1.0.3~13.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-naxsi", rpm:"nginx-mod-naxsi~1.6~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-naxsi-debuginfo", rpm:"nginx-mod-naxsi-debuginfo~1.6~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-naxsi-debugsource", rpm:"nginx-mod-naxsi-debugsource~1.6~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-stream", rpm:"nginx-mod-stream~1.26.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-stream-debuginfo", rpm:"nginx-mod-stream-debuginfo~1.26.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-vts", rpm:"nginx-mod-vts~0.2.2~9.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-vts-debuginfo", rpm:"nginx-mod-vts-debuginfo~0.2.2~9.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-vts-debugsource", rpm:"nginx-mod-vts-debugsource~0.2.2~9.fc40", rls:"FC40"))) {
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

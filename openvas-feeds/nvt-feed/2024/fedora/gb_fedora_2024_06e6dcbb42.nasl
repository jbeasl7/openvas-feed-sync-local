# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887218");
  script_cve_id("CVE-2024-31079", "CVE-2024-32760", "CVE-2024-34161", "CVE-2024-35200");
  script_tag(name:"creation_date", value:"2024-06-09 04:06:45 +0000 (Sun, 09 Jun 2024)");
  script_version("2025-01-27T05:37:51+0000");
  script_tag(name:"last_modification", value:"2025-01-27 05:37:51 +0000 (Mon, 27 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-24 16:21:56 +0000 (Fri, 24 Jan 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2024-06e6dcbb42)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-06e6dcbb42");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-06e6dcbb42");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2283925");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2283932");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2283939");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2283946");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nginx' package(s) announced via the FEDORA-2024-06e6dcbb42 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"*) Security: when using HTTP/3, processing of a specially crafted QUIC
 session might cause a worker process crash, worker process memory
 disclosure on systems with MTU larger than 4096 bytes, or might have
 potential other impact (CVE-2024-32760, CVE-2024-31079,
 CVE-2024-35200, CVE-2024-34161).
 Thanks to Nils Bars of CISPA.

 *) Bugfix: reduced memory consumption for long-lived requests if 'gzip',
 'gunzip', 'ssi', 'sub_filter', or 'grpc_pass' directives are used.

 *) Bugfix: nginx could not be built by gcc 14 if the --with-atomic
 option was used.
 Thanks to Edgar Bonet.

 *) Bugfix: in HTTP/3.");

  script_tag(name:"affected", value:"'nginx' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"nginx", rpm:"nginx~1.26.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-all-modules", rpm:"nginx-all-modules~1.26.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-core", rpm:"nginx-core~1.26.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-core-debuginfo", rpm:"nginx-core-debuginfo~1.26.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-debuginfo", rpm:"nginx-debuginfo~1.26.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-debugsource", rpm:"nginx-debugsource~1.26.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-filesystem", rpm:"nginx-filesystem~1.26.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-devel", rpm:"nginx-mod-devel~1.26.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-image-filter", rpm:"nginx-mod-http-image-filter~1.26.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-image-filter-debuginfo", rpm:"nginx-mod-http-image-filter-debuginfo~1.26.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-perl", rpm:"nginx-mod-http-perl~1.26.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-perl-debuginfo", rpm:"nginx-mod-http-perl-debuginfo~1.26.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-xslt-filter", rpm:"nginx-mod-http-xslt-filter~1.26.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-xslt-filter-debuginfo", rpm:"nginx-mod-http-xslt-filter-debuginfo~1.26.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-mail", rpm:"nginx-mod-mail~1.26.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-mail-debuginfo", rpm:"nginx-mod-mail-debuginfo~1.26.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-stream", rpm:"nginx-mod-stream~1.26.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-stream-debuginfo", rpm:"nginx-mod-stream-debuginfo~1.26.1~1.fc40", rls:"FC40"))) {
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

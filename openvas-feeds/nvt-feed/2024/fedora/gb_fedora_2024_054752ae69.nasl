# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.0547529710169");
  script_cve_id("CVE-2024-9341", "CVE-2024-9407", "CVE-2024-9675", "CVE-2024-9676");
  script_tag(name:"creation_date", value:"2024-11-12 04:08:22 +0000 (Tue, 12 Nov 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-22 19:34:40 +0000 (Fri, 22 Nov 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-054752ae69)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-054752ae69");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-054752ae69");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2315691");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2315887");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2317462");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2317464");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2318511");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2318514");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2319017");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2319019");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'buildah, podman' package(s) announced via the FEDORA-2024-054752ae69 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fixes CVE-2024-9341, CVE-2024-9407, CVE-2024-9675 and CVE-2024-9676.");

  script_tag(name:"affected", value:"'buildah, podman' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"buildah", rpm:"buildah~1.37.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"buildah-debuginfo", rpm:"buildah-debuginfo~1.37.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"buildah-debugsource", rpm:"buildah-debugsource~1.37.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"buildah-tests", rpm:"buildah-tests~1.37.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"buildah-tests-debuginfo", rpm:"buildah-tests-debuginfo~1.37.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~5.2.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-debuginfo", rpm:"podman-debuginfo~5.2.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-debugsource", rpm:"podman-debugsource~5.2.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-docker", rpm:"podman-docker~5.2.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-machine", rpm:"podman-machine~5.2.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-remote", rpm:"podman-remote~5.2.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-remote-debuginfo", rpm:"podman-remote-debuginfo~5.2.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-tests", rpm:"podman-tests~5.2.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-tests-debuginfo", rpm:"podman-tests-debuginfo~5.2.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podmansh", rpm:"podmansh~5.2.5~2.fc40", rls:"FC40"))) {
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

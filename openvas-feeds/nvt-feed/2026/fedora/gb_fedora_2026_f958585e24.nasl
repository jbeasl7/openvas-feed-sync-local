# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.10295858510124");
  script_cve_id("CVE-2026-26981", "CVE-2026-27622");
  script_tag(name:"creation_date", value:"2026-03-17 04:39:08 +0000 (Tue, 17 Mar 2026)");
  script_version("2026-03-17T05:57:27+0000");
  script_tag(name:"last_modification", value:"2026-03-17 05:57:27 +0000 (Tue, 17 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-05 21:07:05 +0000 (Thu, 05 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-f958585e24)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-f958585e24");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-f958585e24");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2442257");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2444289");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-openexr' package(s) announced via the FEDORA-2026-f958585e24 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to openexr-3.4.6 resp 3.3.8.");

  script_tag(name:"affected", value:"'mingw-openexr' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"mingw-openexr", rpm:"mingw-openexr~3.3.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-openexr", rpm:"mingw32-openexr~3.3.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-openexr-debuginfo", rpm:"mingw32-openexr-debuginfo~3.3.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-openexr-tools", rpm:"mingw32-openexr-tools~3.3.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-openexr", rpm:"mingw64-openexr~3.3.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-openexr-debuginfo", rpm:"mingw64-openexr-debuginfo~3.3.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-openexr-tools", rpm:"mingw64-openexr-tools~3.3.8~1.fc43", rls:"FC43"))) {
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

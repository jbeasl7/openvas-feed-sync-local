# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.197910201910260");
  script_cve_id("CVE-2026-4985");
  script_tag(name:"creation_date", value:"2026-04-10 05:05:24 +0000 (Fri, 10 Apr 2026)");
  script_version("2026-04-10T06:15:25+0000");
  script_tag(name:"last_modification", value:"2026-04-10 06:15:25 +0000 (Fri, 10 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-27 22:16:23 +0000 (Fri, 27 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-1a9f019f60)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-1a9f019f60");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-1a9f019f60");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2452785");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libcgif' package(s) announced via the FEDORA-2026-1a9f019f60 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**Version 0.5.3**

- Fix potential undefined behavior in `cgif_addframe` which could have led to an integer overflow **CVE-2026-4985**");

  script_tag(name:"affected", value:"'libcgif' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"libcgif", rpm:"libcgif~0.5.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcgif-debuginfo", rpm:"libcgif-debuginfo~0.5.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcgif-debugsource", rpm:"libcgif-debugsource~0.5.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcgif-devel", rpm:"libcgif-devel~0.5.3~1.fc43", rls:"FC43"))) {
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

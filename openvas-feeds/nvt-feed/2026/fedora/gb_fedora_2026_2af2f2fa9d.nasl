# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.29710221022102979100");
  script_cve_id("CVE-2026-25646");
  script_tag(name:"creation_date", value:"2026-02-23 04:44:29 +0000 (Mon, 23 Feb 2026)");
  script_version("2026-02-23T06:01:22+0000");
  script_tag(name:"last_modification", value:"2026-02-23 06:01:22 +0000 (Mon, 23 Feb 2026)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-13 20:43:44 +0000 (Fri, 13 Feb 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-2af2f2fa9d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-2af2f2fa9d");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-2af2f2fa9d");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2438672");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2438684");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-libpng' package(s) announced via the FEDORA-2026-2af2f2fa9d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to libpng-1.6.55.");

  script_tag(name:"affected", value:"'mingw-libpng' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"mingw-libpng", rpm:"mingw-libpng~1.6.55~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-libpng", rpm:"mingw32-libpng~1.6.55~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-libpng-debuginfo", rpm:"mingw32-libpng-debuginfo~1.6.55~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-libpng-static", rpm:"mingw32-libpng-static~1.6.55~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-libpng", rpm:"mingw64-libpng~1.6.55~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-libpng-debuginfo", rpm:"mingw64-libpng-debuginfo~1.6.55~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-libpng-static", rpm:"mingw64-libpng-static~1.6.55~1.fc42", rls:"FC42"))) {
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

# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.199981001079934");
  script_cve_id("CVE-2026-32777");
  script_tag(name:"creation_date", value:"2026-03-31 04:51:57 +0000 (Tue, 31 Mar 2026)");
  script_version("2026-03-31T06:09:03+0000");
  script_tag(name:"last_modification", value:"2026-03-31 06:09:03 +0000 (Tue, 31 Mar 2026)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-17 15:52:34 +0000 (Tue, 17 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-1cbd107c34)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-1cbd107c34");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-1cbd107c34");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2447973");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-expat' package(s) announced via the FEDORA-2026-1cbd107c34 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 2.7.5.");

  script_tag(name:"affected", value:"'mingw-expat' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"mingw-expat", rpm:"mingw-expat~2.7.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-expat", rpm:"mingw32-expat~2.7.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-expat-debuginfo", rpm:"mingw32-expat-debuginfo~2.7.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-expat-static", rpm:"mingw32-expat-static~2.7.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-expat", rpm:"mingw64-expat~2.7.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-expat-debuginfo", rpm:"mingw64-expat-debuginfo~2.7.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-expat-static", rpm:"mingw64-expat-static~2.7.5~1.fc42", rls:"FC42"))) {
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

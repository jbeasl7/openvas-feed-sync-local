# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.19749397989967");
  script_cve_id("CVE-2024-9287");
  script_tag(name:"creation_date", value:"2024-12-16 04:08:55 +0000 (Mon, 16 Dec 2024)");
  script_version("2025-02-11T12:33:12+0000");
  script_tag(name:"last_modification", value:"2025-02-11 12:33:12 +0000 (Tue, 11 Feb 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-10 18:47:16 +0000 (Mon, 10 Feb 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2024-1a493abc67)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-1a493abc67");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-1a493abc67");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2321654");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/103848");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/122792");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/124651");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.10' package(s) announced via the FEDORA-2024-1a493abc67 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Python 3.10.16 security release.

Security content in this release
--------------------------------

- [gh-122792]([link moved to references]): Changed IPv4-mapped `ipaddress.IPv6Address` to consistently use the mapped IPv4 address value for deciding properties. Properties which have their behavior fixed are `is_multicast`, `is_reserved`, `is_link_local`, `is_global`, and `is_unspecified`.
- CVE-2024-9287: [gh-124651]([link moved to references]): Properly quote template strings in `venv` activation scripts.
- [gh-103848]([link moved to references]): Added checks to ensure that [ bracketed ] hosts found by `urllib.parse.urlsplit()` are of IPv6 or IPvFuture format.");

  script_tag(name:"affected", value:"'python3.10' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3.10", rpm:"python3.10~3.10.16~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.10-debug", rpm:"python3.10-debug~3.10.16~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.10-debuginfo", rpm:"python3.10-debuginfo~3.10.16~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.10-debugsource", rpm:"python3.10-debugsource~3.10.16~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.10-devel", rpm:"python3.10-devel~3.10.16~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.10-idle", rpm:"python3.10-idle~3.10.16~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.10-libs", rpm:"python3.10-libs~3.10.16~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.10-test", rpm:"python3.10-test~3.10.16~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.10-tkinter", rpm:"python3.10-tkinter~3.10.16~1.fc40", rls:"FC40"))) {
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

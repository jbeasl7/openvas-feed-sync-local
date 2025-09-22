# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.100598100698621014");
  script_cve_id("CVE-2023-49081", "CVE-2023-49082");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2025-01-14T05:37:03+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:03 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-29 20:15:08 +0000 (Wed, 29 Nov 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-d5bd6b62e4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-d5bd6b62e4");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-d5bd6b62e4");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2252235");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2252236");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2252248");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2252249");
  script_xref(name:"URL", value:"https://github.com/aio-libs/aiohttp/releases/tag/v3.9.0");
  script_xref(name:"URL", value:"https://github.com/aio-libs/aiohttp/releases/tag/v3.9.1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-aiohttp, python-pysqueezebox, python-wled' package(s) announced via the FEDORA-2023-d5bd6b62e4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fix for CVE-2023-49081, CVE-2023-49082.

Update `python-aiohttp` to 3.9.1.

Patch `python-pysqeezebox` and `python-wled` so they do not have an implicit dependency on `python-async-timeout` via `python-aiohttp`.

[links moved to references]");

  script_tag(name:"affected", value:"'python-aiohttp, python-pysqueezebox, python-wled' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-aiohttp", rpm:"python-aiohttp~3.9.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-aiohttp-debugsource", rpm:"python-aiohttp-debugsource~3.9.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pysqueezebox", rpm:"python-pysqueezebox~0.5.5~11.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-wled", rpm:"python-wled~0.4.4~11.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-aiohttp+speedups", rpm:"python3-aiohttp+speedups~3.9.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-aiohttp", rpm:"python3-aiohttp~3.9.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-aiohttp-debuginfo", rpm:"python3-aiohttp-debuginfo~3.9.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pysqueezebox", rpm:"python3-pysqueezebox~0.5.5~11.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-wled", rpm:"python3-wled~0.4.4~11.fc40", rls:"FC40"))) {
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

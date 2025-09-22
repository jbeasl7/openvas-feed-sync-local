# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.102161598581016");
  script_cve_id("CVE-2024-47874");
  script_tag(name:"creation_date", value:"2024-10-24 04:08:58 +0000 (Thu, 24 Oct 2024)");
  script_version("2024-10-25T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-10-25 05:05:38 +0000 (Fri, 25 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-f1615b58e6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-f1615b58e6");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-f1615b58e6");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2318804");
  script_xref(name:"URL", value:"https://github.com/encode/starlette/commit/fd038f3070c302bff17ef7d173dbb0b007617733");
  script_xref(name:"URL", value:"https://github.com/encode/starlette/security/advisories/GHSA-f96h-pmfr-66vw");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-fastapi, python-openapi-core, python-platformio, python-starlette' package(s) announced via the FEDORA-2024-f1615b58e6 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fix for CVE-2024-47874.

## Starlette 0.40.0 (October 15, 2024)

This release fixes a Denial of service (DoS) via `multipart/form-data` requests.

You can view the full security advisory:
[GHSA-f96h-pmfr-66vw]([link moved to references])

#### Fixed

- Add `max_part_size` to `MultiPartParser` to limit the size of parts in `multipart/form-data`
 requests [fd038f3]([link moved to references]).");

  script_tag(name:"affected", value:"'python-fastapi, python-openapi-core, python-platformio, python-starlette' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"platformio", rpm:"platformio~6.1.14~7.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-fastapi", rpm:"python-fastapi~0.111.1~7.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-openapi-core", rpm:"python-openapi-core~0.19.4~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-platformio", rpm:"python-platformio~6.1.14~7.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-starlette", rpm:"python-starlette~0.40.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fastapi+all", rpm:"python3-fastapi+all~0.111.1~7.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fastapi", rpm:"python3-fastapi~0.111.1~7.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fastapi-slim+all", rpm:"python3-fastapi-slim+all~0.111.1~7.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fastapi-slim+standard", rpm:"python3-fastapi-slim+standard~0.111.1~7.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fastapi-slim", rpm:"python3-fastapi-slim~0.111.1~7.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core+aiohttp", rpm:"python3-openapi-core+aiohttp~0.19.4~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core+django", rpm:"python3-openapi-core+django~0.19.4~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core+falcon", rpm:"python3-openapi-core+falcon~0.19.4~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core+fastapi", rpm:"python3-openapi-core+fastapi~0.19.4~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core+flask", rpm:"python3-openapi-core+flask~0.19.4~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core+requests", rpm:"python3-openapi-core+requests~0.19.4~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core+starlette", rpm:"python3-openapi-core+starlette~0.19.4~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core", rpm:"python3-openapi-core~0.19.4~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-platformio", rpm:"python3-platformio~6.1.14~7.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-starlette+full", rpm:"python3-starlette+full~0.40.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-starlette", rpm:"python3-starlette~0.40.0~1.fc40", rls:"FC40"))) {
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

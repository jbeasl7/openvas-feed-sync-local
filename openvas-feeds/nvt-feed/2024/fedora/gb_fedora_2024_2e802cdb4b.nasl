# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886298");
  script_tag(name:"creation_date", value:"2024-03-25 09:37:11 +0000 (Mon, 25 Mar 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-2e802cdb4b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-2e802cdb4b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-2e802cdb4b");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2262502");
  script_xref(name:"URL", value:"https://github.com/andrew-d/python-multipart/pull/75");
  script_xref(name:"URL", value:"https://github.com/tiangolo/fastapi/security/advisories/GHSA-qf9m-vfgh-m389");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-fastapi, python-multipart' package(s) announced via the FEDORA-2024-2e802cdb4b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"## `python-multipart` 0.0.7 (2024-02-03)

* Refactor header option parser to use the standard library instead of a custom RegEx [#75]([link moved to references]).

Fixes a denial of service vulnerability, [GHSA-qf9m-vfgh-m389]([link moved to references]), initially reported in FastAPI but applicable to other libraries and applications.");

  script_tag(name:"affected", value:"'python-fastapi, python-multipart' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"python-fastapi", rpm:"python-fastapi~0.103.0~10.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-multipart", rpm:"python-multipart~0.0.7~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fastapi+all", rpm:"python3-fastapi+all~0.103.0~10.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fastapi", rpm:"python3-fastapi~0.103.0~10.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-multipart", rpm:"python3-multipart~0.0.7~1.fc39", rls:"FC39"))) {
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

# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.474710210273973");
  script_cve_id("CVE-2026-30892");
  script_tag(name:"creation_date", value:"2026-04-02 04:48:18 +0000 (Thu, 02 Apr 2026)");
  script_version("2026-04-02T06:06:11+0000");
  script_tag(name:"last_modification", value:"2026-04-02 06:06:11 +0000 (Thu, 02 Apr 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-26 20:53:32 +0000 (Thu, 26 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-4747ff73a3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-4747ff73a3");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-4747ff73a3");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2452163");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'crun' package(s) announced via the FEDORA-2026-4747ff73a3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for crun-1.27-1.fc43.

##### **Changelog for crun**

```
* Wed Mar 25 2026 Packit <hello@packit.dev> - 1.27-1
- Update to 1.27 upstream release

* Mon Dec 22 2025 Packit <hello@packit.dev> - 1.26-1
- Update to 1.26 upstream release

```");

  script_tag(name:"affected", value:"'crun' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"crun", rpm:"crun~1.27~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crun-debuginfo", rpm:"crun-debuginfo~1.27~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crun-debugsource", rpm:"crun-debugsource~1.27~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crun-krun", rpm:"crun-krun~1.27~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crun-wasm", rpm:"crun-wasm~1.27~1.fc43", rls:"FC43"))) {
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

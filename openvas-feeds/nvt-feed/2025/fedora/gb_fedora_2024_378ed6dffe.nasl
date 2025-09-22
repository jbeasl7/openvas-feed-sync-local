# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.3781011006100102102101");
  script_cve_id("CVE-2024-24789", "CVE-2024-53858", "CVE-2024-54132");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-18 17:58:22 +0000 (Tue, 18 Jun 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-378ed6dffe)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-378ed6dffe");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-378ed6dffe");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273304");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2292682");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2322519");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2329265");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2330387");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2330388");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gh' package(s) announced via the FEDORA-2024-378ed6dffe advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for gh-2.63.2-1.fc42.

##### **Changelog**

```
* Tue Dec 10 2024 Mikel Olasagasti Uranga <mikel@olasagasti.info> - 2.63.2-1
- Update to 2.63.2 - Closes rhbz#2273304 rhbz#2292682 rhbz#2322519
 rhbz#2329265 rhbz#2330387 rhbz#2330388

```");

  script_tag(name:"affected", value:"'gh' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"gh", rpm:"gh~2.63.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gh-debuginfo", rpm:"gh-debuginfo~2.63.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gh-debugsource", rpm:"gh-debugsource~2.63.2~1.fc42", rls:"FC42"))) {
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

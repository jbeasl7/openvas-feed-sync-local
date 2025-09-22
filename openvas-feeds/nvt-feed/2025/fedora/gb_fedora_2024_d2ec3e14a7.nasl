# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.100210199310114977");
  script_cve_id("CVE-2024-24789");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-18 17:58:22 +0000 (Tue, 18 Jun 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-d2ec3e14a7)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-d2ec3e14a7");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-d2ec3e14a7");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2292712");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kitty' package(s) announced via the FEDORA-2024-d2ec3e14a7 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for kitty-0.35.1-4.fc41.

##### **Changelog**

```
* Mon Jun 17 2024 Pavel Solovev <daron439@gmail.com> - 0.35.1-4
- rebuild for rhbz#2292712

```");

  script_tag(name:"affected", value:"'kitty' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"kitty", rpm:"kitty~0.35.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kitty-debuginfo", rpm:"kitty-debuginfo~0.35.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kitty-debugsource", rpm:"kitty-debugsource~0.35.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kitty-doc", rpm:"kitty-doc~0.35.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kitty-kitten", rpm:"kitty-kitten~0.35.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kitty-kitten-debuginfo", rpm:"kitty-kitten-debuginfo~0.35.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kitty-shell-integration", rpm:"kitty-shell-integration~0.35.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kitty-terminfo", rpm:"kitty-terminfo~0.35.1~4.fc41", rls:"FC41"))) {
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

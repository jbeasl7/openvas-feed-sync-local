# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.98100810210142929");
  script_cve_id("CVE-2023-49295", "CVE-2024-22189", "CVE-2024-27289", "CVE-2024-27304", "CVE-2024-28180");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-19 19:05:52 +0000 (Fri, 19 Jan 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-bd8fe42929)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-bd8fe42929");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-bd8fe42929");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2257829");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268278");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268468");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268877");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273517");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278549");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'caddy' package(s) announced via the FEDORA-2024-bd8fe42929 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for caddy-2.8.4-1.fc41.

##### **Changelog**

```
* Fri Jul 5 2024 Carl George <carlwgeorge@fedoraproject.org> - 2.8.4-1
- Update to version 2.8.4 rhbz#2278549
- Resolves CVE-2023-49295 rhbz#2257829
- Resolves CVE-2024-27304 rhbz#2268278
- Resolves CVE-2024-27289 rhbz#2268468
- Resolves CVE-2024-28180 rhbz#2268877
- Resolves CVE-2024-22189 rhbz#2273517
- Remove LimitNPROC from systemd unit files

```");

  script_tag(name:"affected", value:"'caddy' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"caddy", rpm:"caddy~2.8.4~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"caddy-debuginfo", rpm:"caddy-debuginfo~2.8.4~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"caddy-debugsource", rpm:"caddy-debugsource~2.8.4~1.fc41", rls:"FC41"))) {
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

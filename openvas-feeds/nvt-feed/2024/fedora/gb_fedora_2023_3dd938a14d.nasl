# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.31001009389714100");
  script_cve_id("CVE-2022-30256", "CVE-2023-31137");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-16 16:47:46 +0000 (Tue, 16 May 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-3dd938a14d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-3dd938a14d");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-3dd938a14d");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2149110");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2180267");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2207551");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'maradns' package(s) announced via the FEDORA-2023-3dd938a14d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for maradns-3.5.0036-1.fc39.

##### **Changelog**

```
* Tue May 16 2023 Tomasz Torcz <ttorcz@fedoraproject.org> - 3.5.0036-1
- new version 3.5.0036 (rhbz#2149110, rhbz#2180267)
- fixes CVE-2023-31137 (rhbz#2207551)

```");

  script_tag(name:"affected", value:"'maradns' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"maradns", rpm:"maradns~3.5.0036~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maradns-debuginfo", rpm:"maradns-debuginfo~3.5.0036~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maradns-debugsource", rpm:"maradns-debugsource~3.5.0036~1.fc39", rls:"FC39"))) {
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

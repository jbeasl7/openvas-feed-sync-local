# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.2102095798051");
  script_cve_id("CVE-2022-41717", "CVE-2022-41723");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-09 16:36:40 +0000 (Thu, 09 Mar 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-2f0957b051)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-2f0957b051");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-2f0957b051");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2155701");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2163286");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2171700");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2178480");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2226392");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_38_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_39_Mass_Rebuild");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rclone' package(s) announced via the FEDORA-2023-2f0957b051 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for rclone-1.63.1-1.fc39.

##### **Changelog**

```
* Mon Jul 31 2023 Mikel Olasagasti Uranga <mikel@olasagasti.info> - 1.63.1-1
- Update to 1.63.1 - Closes rhbz#2155701 rhbz#2163286 rhbz#2171700
 rhbz#2178480 rhbz#2226392
- Don't build storj backend by default
- Use shell completion macros
* Fri Jul 21 2023 Fedora Release Engineering <releng@fedoraproject.org> - 1.60.1-3
- Rebuilt for [link moved to references]
* Fri Jan 20 2023 Fedora Release Engineering <releng@fedoraproject.org> - 1.60.1-2
- Rebuilt for [link moved to references]

```");

  script_tag(name:"affected", value:"'rclone' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"rclone", rpm:"rclone~1.63.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rclone-debuginfo", rpm:"rclone-debuginfo~1.63.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rclone-debugsource", rpm:"rclone-debugsource~1.63.1~1.fc39", rls:"FC39"))) {
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

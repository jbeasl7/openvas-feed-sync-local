# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.99171011020102176");
  script_cve_id("CVE-2023-30536", "CVE-2023-44270", "CVE-2024-2961", "CVE-2024-55565", "CVE-2024-56519", "CVE-2024-56521", "CVE-2024-56522", "CVE-2024-56527");
  script_tag(name:"creation_date", value:"2025-01-31 04:08:17 +0000 (Fri, 31 Jan 2025)");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-01 16:38:35 +0000 (Mon, 01 May 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2025-c17ef0f176)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-c17ef0f176");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-c17ef0f176");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2328680");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331101");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2334290");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2334295");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2334299");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2334343");
  script_xref(name:"URL", value:"https://github.com/phpmyadmin/phpmyadmin/blob/RELEASE_5_2_2/ChangeLog");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpMyAdmin' package(s) announced via the FEDORA-2025-c17ef0f176 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**phpMyAdmin 5.2.2 is released**

Welcome to the release of phpMyAdmin version 5.2.2, the 'I should have released this sooner' release. This is primarily a bugfix release but also contains a few security fixes as noted below.

* fix possible security issue in sql-parser which could cause long execution times that could create a DOS attack (thanks to Maximilian Krog)
* fix an XSS vulnerability in the check tables feature (**PMASA-2025-1**, thanks to bluebird)
* fix an XSS vulnerability in the Insert tab (**PMASA-2025-2**, thanks to frequent contributor Kamil Tekiela)
* fix possible security issue with library code slim/psr7 (**CVE-2023-30536**)
* fix possible security issue relating to iconv (**CVE-2024-2961, PMASA-2025-3**)
* fix a full path disclosure in the Monitoring tab
* issue #18268 Fix UI issue the theme manager is disabled
* issue Allow opening server breadcrumb links in new tab with Ctrl/Meta key
* issue #19141 Add cookie prefix '-__Secure-' to cookies to help prevent cookie smuggling
* issue #18106 Fix renaming database with a view
* issue #18120 Fix bug with numerical tables during renaming database
* issue #16851 Fix ($cfg['Order']) default column order doesn't have have any effect since phpMyAdmin 4.2.0
* issue #18258 Speed improvements when exporting a database
* issue #18769 Improved collations support for MariaDB 10.10

There are many, many more fixes that you can see in the ChangeLog file included with this release or [online]([link moved to references])");

  script_tag(name:"affected", value:"'phpMyAdmin' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"phpMyAdmin", rpm:"phpMyAdmin~5.2.2~1.fc40", rls:"FC40"))) {
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

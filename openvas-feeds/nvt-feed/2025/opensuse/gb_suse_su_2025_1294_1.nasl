# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.1294.1");
  script_cve_id("CVE-2020-36327");
  script_tag(name:"creation_date", value:"2025-04-18 04:06:17 +0000 (Fri, 18 Apr 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-17 19:03:14 +0000 (Mon, 17 May 2021)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:1294-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1294-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251294-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185842");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-April/020715.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem-bundler' package(s) announced via the SUSE-SU-2025:1294-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rubygem-bundler fixes the following issues:

- CVE-2020-36327: Fixed bundler choosing a dependency source based
 on the highest gem version number, which means that a rogue gem
 found at a public source may be chosen (bsc#1185842)

Other fixes:
- Updated to version 2.2.34");

  script_tag(name:"affected", value:"'rubygem-bundler' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-bundler", rpm:"ruby2.5-rubygem-bundler~2.2.34~150000.3.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-bundler-doc", rpm:"ruby2.5-rubygem-bundler-doc~2.2.34~150000.3.11.1", rls:"openSUSELeap15.6"))) {
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

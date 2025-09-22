# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.02679.1");
  script_cve_id("CVE-2025-27151", "CVE-2025-32023", "CVE-2025-48367");
  script_tag(name:"creation_date", value:"2025-08-06 04:21:55 +0000 (Wed, 06 Aug 2025)");
  script_version("2025-08-22T05:39:46+0000");
  script_tag(name:"last_modification", value:"2025-08-22 05:39:46 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-21 22:28:57 +0000 (Thu, 21 Aug 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:02679-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02679-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502679-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246059");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041076.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'redis' package(s) announced via the SUSE-SU-2025:02679-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for redis fixes the following issues:

- CVE-2025-27151: Fixed absence of filename size check may cause a stack overflow. (bsc#1243804)
- CVE-2025-32023: Fixed out-of-bounds write when working with HyperLogLog commands can lead to remote code execution. (bsc#1246059)
- CVE-2025-48367: Fixed unauthenticated connection causing repeated IP protocol erros can lead to client starvation and DoS. (bsc#1246058)");

  script_tag(name:"affected", value:"'redis' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"redis7", rpm:"redis7~7.0.8~150600.8.16.1", rls:"openSUSELeap15.6"))) {
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

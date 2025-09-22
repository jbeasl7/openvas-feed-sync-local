# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2860.1");
  script_cve_id("CVE-2024-41671", "CVE-2024-41810");
  script_tag(name:"creation_date", value:"2024-08-12 04:24:46 +0000 (Mon, 12 Aug 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-11 16:17:45 +0000 (Wed, 11 Sep 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2860-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2860-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242860-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228552");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-August/019163.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3-Twisted' package(s) announced via the SUSE-SU-2024:2860-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python3-Twisted fixes the following issues:

- CVE-2024-41671: Fixed HTTP pipelined requests processed out of order in twisted.web (bsc#1228549)
- CVE-2024-41810: Fixed reflected XSS via HTML Injection in Redirect Response (bsc#1228552)");

  script_tag(name:"affected", value:"'python3-Twisted' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"python3-Twisted", rpm:"python3-Twisted~22.2.0~150400.21.1", rls:"SLES15.0SP4"))) {
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

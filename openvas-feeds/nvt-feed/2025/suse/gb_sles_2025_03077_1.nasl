# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.03077.1");
  script_cve_id("CVE-2024-58266");
  script_tag(name:"creation_date", value:"2025-09-08 04:12:00 +0000 (Mon, 08 Sep 2025)");
  script_version("2025-09-08T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-09-08 05:38:50 +0000 (Mon, 08 Sep 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-07 15:18:56 +0000 (Thu, 07 Aug 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:03077-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03077-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503077-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230028");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247207");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041515.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rav1e' package(s) announced via the SUSE-SU-2025:03077-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rav1e fixes the following issues:

- CVE-2024-58266: shlex: Fixed certain bytes allowed to appear unquoted and unescaped in command arguments (bsc#1247207)");

  script_tag(name:"affected", value:"'rav1e' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"librav1e0_6", rpm:"librav1e0_6~0.6.6~150600.3.6.1", rls:"SLES15.0SP6"))) {
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

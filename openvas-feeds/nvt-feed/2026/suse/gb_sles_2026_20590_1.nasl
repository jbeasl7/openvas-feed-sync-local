# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20590.1");
  script_cve_id("CVE-2025-8746");
  script_tag(name:"creation_date", value:"2026-03-09 04:38:35 +0000 (Mon, 09 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-16 15:36:22 +0000 (Tue, 16 Sep 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20590-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20590-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620590-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247921");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024617.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'autogen' package(s) announced via the SUSE-SU-2026:20590-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for autogen fixes the following issues:

- CVE-2025-8746: Fixed improper input validation and memory bounds checking
 when processing certain malformed configuration files (bsc#1247921)");

  script_tag(name:"affected", value:"'autogen' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"autogen", rpm:"autogen~5.18.16~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autoopts", rpm:"autoopts~5.18.16~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopts25", rpm:"libopts25~5.18.16~160000.3.1", rls:"SLES16.0.0"))) {
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

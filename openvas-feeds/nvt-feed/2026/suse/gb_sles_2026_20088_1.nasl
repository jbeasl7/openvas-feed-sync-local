# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20088.1");
  script_cve_id("CVE-2025-48038", "CVE-2025-48039", "CVE-2025-48040");
  script_tag(name:"creation_date", value:"2026-01-22 04:25:52 +0000 (Thu, 22 Jan 2026)");
  script_version("2026-01-28T05:49:43+0000");
  script_tag(name:"last_modification", value:"2026-01-28 05:49:43 +0000 (Wed, 28 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20088-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20088-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620088-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249469");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249470");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249472");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023812.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'erlang' package(s) announced via the SUSE-SU-2026:20088-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for erlang fixes the following issues:

Update the ssh component to the latest in the maint-27 branch.

Security issues fixed:

- CVE-2025-48040: ssh: overly tolerant handling of data received from unauthenticated users when processing key
 exchange messages may lead to excessive resource consumption (bsc#1249472).
- CVE-2025-48039: ssh: unverified paths from authenticated SFTP users may lead to excessive resource consumption
 (bsc#1249469).
- CVE-2025-48038: ssh: unverified file handles from authenticated SFTP users may lead to excessive resource consumption
 (bsc#1249470).");

  script_tag(name:"affected", value:"'erlang' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"erlang", rpm:"erlang~27.1.3~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-epmd", rpm:"erlang-epmd~27.1.3~160000.3.1", rls:"SLES16.0.0"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.0623.1");
  script_cve_id("CVE-2024-11741", "CVE-2024-28180", "CVE-2024-45339", "CVE-2025-21613");
  script_tag(name:"creation_date", value:"2025-02-24 04:07:13 +0000 (Mon, 24 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0623-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0623-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250623-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235574");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236734");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-February/020388.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grafana' package(s) announced via the SUSE-SU-2025:0623-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for grafana fixes the following issues:

grafana was updated from version 10.4.13 to 10.4.15:

- Security issues fixed:
 * CVE-2024-45339: Fixed vulnerability when creating log files (bsc#1236559)
 * CVE-2024-11741: Fixed the Grafana Alerting VictorOps integration (bsc#1236734)
 * CVE-2025-21613: Removed vulnerable library github.com/go-git/go-git/v5 (bsc#1235574)
 * CVE-2024-28180: Fixed improper handling of highly compressed data (bsc#1235206)
- Other bugs fixed and changes:
 * Alerting: Do not fetch Orgs if the user is authenticated by apikey/sa or render key
 * Added provisioning directories
 * Use /bin/bash in wrapper scripts");

  script_tag(name:"affected", value:"'grafana' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"grafana", rpm:"grafana~10.4.15~150200.3.64.1", rls:"openSUSELeap15.6"))) {
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

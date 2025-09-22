# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.1102.1");
  script_cve_id("CVE-2024-23650", "CVE-2024-23653", "CVE-2024-29018", "CVE-2024-41110", "CVE-2025-22868", "CVE-2025-22869");
  script_tag(name:"creation_date", value:"2025-04-04 04:08:24 +0000 (Fri, 04 Apr 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 01:44:46 +0000 (Fri, 09 Feb 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:1102-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1102-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251102-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234089");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239322");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-April/038883.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker, docker-stable' package(s) announced via the SUSE-SU-2025:1102-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for docker, docker-stable fixes the following issues:

- CVE-2025-22868: Fixed unexpected memory consumption during token parsing in golang.org/x/oauth2 (bsc#1239185).
- CVE-2025-22869: Fixed Denial of Service in the Key Exchange of golang.org/x/crypto/ssh (bsc#1239322).
- CVE-2024-29018: Fixed external DNS requests from 'internal' networks leading to data exfiltration (bsc#1234089).
- CVE-2024-23650: Fixed BuildKit daemon crash via malicious BuildKit client or frontend request (bsc#1219437).

Other fixes:
- Make container-selinux requirement conditional on selinux-policy (bsc#1237367).
- Updated docker-buildx to 0.19.3.");

  script_tag(name:"affected", value:"'docker, docker-stable' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~27.5.1_ce~98.126.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~27.5.1_ce~98.126.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-stable", rpm:"docker-stable~24.0.9_ce~1.11.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-stable-bash-completion", rpm:"docker-stable-bash-completion~24.0.9_ce~1.11.1", rls:"SLES12.0SP5"))) {
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

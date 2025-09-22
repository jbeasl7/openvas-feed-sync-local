# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833361");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-46146", "CVE-2023-22644");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-02 16:09:51 +0000 (Fri, 02 Dec 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 12:54:18 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for SUSE Manager Server 4.2 (SUSE-SU-2023:2594-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2594-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/M2OEYNJ37UV6UO75W4Y4RN6XW6WUPV7T");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE Manager Server 4.2'
  package(s) announced via the SUSE-SU-2023:2594-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

  release-notes-susemanager-proxy:

  * Update to 4.2.13

  * Bugs mentioned: bsc#1179747, bsc#1207814, bsc#1209231, bsc#1210437,
      bsc#1210458

  ## Security update for SUSE Manager Server 4.2

  ### Description:

  This update fixes the following issues:

  release-notes-susemanager:

  * Update to 4.2.13

  * Salt has been upgraded to 3006.0

  * SUSE Linux Enterprise Server 15 SP5 Family support has been added

  * openSUSE Leap 15.5 support has been added

  * Automatic migration from Salt 3000 to Salt bundle

  * Grafana upgraded to 9.5.1

  * Node exporter upgraded to 1.5.0

  * Prometheus upgraded to 2.37.6

  * Postgres exporter upgraded to 0.10.1

  * CVEs fixed: CVE-2023-22644, CVE-2022-46146

  * Bugs mentioned: bsc#1179747, bsc#1186011, bsc#1203599, bsc#1205600,
      bsc#1206423 bsc#1207550, bsc#1207814, bsc#1207941, bsc#1208984, bsc#1209220
      bsc#1209231, bsc#1209277, bsc#1209386, bsc#1209434, bsc#1209508 bsc#1209877,
      bsc#1209915, bsc#1209926, bsc#1210011, bsc#1210086 bsc#1210101, bsc#1210107,
      bsc#1210154, bsc#1210162, bsc#1210232 bsc#1210311, bsc#1210406, bsc#1210437,
      bsc#1210458, bsc#1210659 bsc#1210835, bsc#1210957, bsc#1211330, bsc#1208046,
      bsc#1212517 bsc#1212096

  ##");

  script_tag(name:"affected", value:"'SUSE Manager Server 4.2' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"release-notes-susemanager", rpm:"release-notes-susemanager~4.2.13~150300.3.81.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"release-notes-susemanager-proxy", rpm:"release-notes-susemanager-proxy~4.2.13~150300.3.64.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"release-notes-susemanager", rpm:"release-notes-susemanager~4.2.13~150300.3.81.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"release-notes-susemanager-proxy", rpm:"release-notes-susemanager-proxy~4.2.13~150300.3.64.2", rls:"openSUSELeap15.3"))) {
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
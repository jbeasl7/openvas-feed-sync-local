# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2024.0384.1");
  script_cve_id("CVE-2024-22114", "CVE-2024-36461");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-10 16:15:23 +0000 (Tue, 10 Dec 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0384-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0384-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/C6HFPCXWPBUGZ3BE7T5OXXTSGEHUCHFU/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229204");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zabbix' package(s) announced via the openSUSE-SU-2024:0384-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for zabbix fixes the following issues:

Zabbix was updated to 6.0.33:

- this version fixes CVE-2024-36461 and CVE-2024-22114
- New Features and Improvements

 + ZBXNEXT-9000 Changed query table for ASM disk group metrics in Oracle Database plugin and
 Oracle by ODBC template Agent Templates
 + ZBXNEXT-9217 Added AWS Lambda by HTTP template Templates
 + ZBXNEXT-9293 Updated max supported MySQL version to 9.0 Proxy Server
 + ZBXNEXT-8657 Updated Zabbix health templates with new visualization Templates
 + ZBXNEXT-9143 Added index on auditlog recordsetid Server
 + ZBXNEXT-9081 Added Small Computer System Interface (SCSI) device type support to Zabbix agent 2 Smart plugin Agent
 + ZBXNEXT-6445 Added recovery expression for fuzzytime triggers in Linux and Windows templates,
 removed fuzzytime triggers from active agent templates Templates
 + ZBXNEXT-9201 Updated max supported MySQL version to 8.4 Proxy Server
 + ZBXNEXT-9225 Updated max supported TimescaleDB version to 2.15 Server
 + ZBXNEXT-9226 Updated max supported MariaDB version to 11.4 Proxy Server
 + ZBXNEXT-8868 Added discovery and template for Azure VM Scale Sets Templates

- Bug Fixes

 + BX-24947 Fixed PHP runtime errors while processing frontend notifications Frontend
 + ZBX-24824 Improved loadable plugin connection broker Agent
 + ZBX-24583 Fixed inability to export/import web scenario with digest authentication API
 + ZBX-23905 Fixed double scroll in script dialogs Frontend
 + ZBX-18767 Fixed word breaks in flexible text input fields and trigger expressions Frontend
 + ZBX-24909 Fixed resolving of macro functions in the 'Item value' widget Frontend
 + ZBX-24859 Fixed JavaScript in S3 buckets discovery rule Templates
 + ZBX-24617 Fixed hardcoded region in AWS by HTTP template Templates
 + ZBX-24524 Fixed 'New values per second' statistic to include dependent items in calculation Proxy Server
 + ZBX-24821 Made 'execute_on' value being recorded in audit only for shell scripts Server
 + ZBX-23312 Fixed discovery edit form being saved incorrectly after dcheck update Frontend
 + ZBX-24773 Fixed duplicate item preprocessing in Kubernetes Kubelet by HTTP template Templates
 + ZBX-24514 Fixed standalone Zabbix server and Zabbix proxy not stopping when database is read-only Proxy Server
 + ZBX-23936 Fixed state and styling of readonly fields Frontend
 + ZBX-24520 Fixed an issue with incorrect translations used in several frontend places Frontend
 + ZBX-21815 Fixed issue with undefined offset for media type when it was deleted before saving the user Frontend
 + ZBX-24108 Fixed error in dashboard if Map widget contains map element that user doesn't have access to Frontend
 + ZBX-24569 Fixed old and added new items to Azure Virtual Machine template Templates
 + ZBX-24537 Fixed tags subfilter in Latest data kiosk mode Frontend
 + ZBX-24167 Fixed template linkage when item prototype collision is found Server
 + ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'zabbix' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"system-user-zabbix", rpm:"system-user-zabbix~6.0.33~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-agent", rpm:"zabbix-agent~6.0.33~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-java-gateway", rpm:"zabbix-java-gateway~6.0.33~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy", rpm:"zabbix-proxy~6.0.33~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-mysql", rpm:"zabbix-proxy-mysql~6.0.33~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-postgresql", rpm:"zabbix-proxy-postgresql~6.0.33~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-sqlite", rpm:"zabbix-proxy-sqlite~6.0.33~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server", rpm:"zabbix-server~6.0.33~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-mysql", rpm:"zabbix-server-mysql~6.0.33~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-postgresql", rpm:"zabbix-server-postgresql~6.0.33~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-ui", rpm:"zabbix-ui~6.0.33~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
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

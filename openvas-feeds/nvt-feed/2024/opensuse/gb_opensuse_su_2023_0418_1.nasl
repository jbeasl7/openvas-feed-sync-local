# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833416");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-32727");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-22 17:48:43 +0000 (Fri, 22 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:21:32 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for zabbix (openSUSE-SU-2023:0418-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0418-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2JA2U5HZXB4P57NCP4OYCXTIJXPC56ZT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zabbix'
  package(s) announced via the openSUSE-SU-2023:0418-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for zabbix fixes the following issues:

     Updated to latest release 4.0.50:

  - CVE-2023-32727: Fixed potential arbitrary code execution in icmpping
       (boo#1218199)");

  script_tag(name:"affected", value:"'zabbix' package(s) on openSUSE Backports SLE-15-SP5.");

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

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"zabbix-agent", rpm:"zabbix-agent~4.0.50~bp155.3.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-java-gateway", rpm:"zabbix-java-gateway~4.0.50~bp155.3.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-phpfrontend", rpm:"zabbix-phpfrontend~4.0.50~bp155.3.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy", rpm:"zabbix-proxy~4.0.50~bp155.3.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-mysql", rpm:"zabbix-proxy-mysql~4.0.50~bp155.3.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-postgresql", rpm:"zabbix-proxy-postgresql~4.0.50~bp155.3.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-sqlite", rpm:"zabbix-proxy-sqlite~4.0.50~bp155.3.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server", rpm:"zabbix-server~4.0.50~bp155.3.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-mysql", rpm:"zabbix-server-mysql~4.0.50~bp155.3.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-postgresql", rpm:"zabbix-server-postgresql~4.0.50~bp155.3.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-agent", rpm:"zabbix-agent~4.0.50~bp155.3.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-java-gateway", rpm:"zabbix-java-gateway~4.0.50~bp155.3.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-phpfrontend", rpm:"zabbix-phpfrontend~4.0.50~bp155.3.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy", rpm:"zabbix-proxy~4.0.50~bp155.3.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-mysql", rpm:"zabbix-proxy-mysql~4.0.50~bp155.3.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-postgresql", rpm:"zabbix-proxy-postgresql~4.0.50~bp155.3.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-proxy-sqlite", rpm:"zabbix-proxy-sqlite~4.0.50~bp155.3.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server", rpm:"zabbix-server~4.0.50~bp155.3.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-mysql", rpm:"zabbix-server-mysql~4.0.50~bp155.3.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zabbix-server-postgresql", rpm:"zabbix-server-postgresql~4.0.50~bp155.3.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
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
# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833609");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-2183", "CVE-2023-2801", "CVE-2023-3128");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-30 17:49:02 +0000 (Fri, 30 Jun 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:36:40 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for SUSE Manager Client Tools (SUSE-SU-2023:2917-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2917-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JIWYJVA3YTYJ5SV333UL44WEQRVUWYQN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE Manager Client Tools'
  package(s) announced via the SUSE-SU-2023:2917-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

  grafana:

  * Update to version 9.5.5:

  * CVE-2023-3128: Fix authentication bypass using Azure AD OAuth (bsc#1212641,
      jsc#PED-3694)

  * Bug fixes:

  * Auth: Show invite button if disable login form is set to false.

  * Azure: Fix Kusto auto-completion for Azure datasources.

  * RBAC: Remove legacy AC editor and admin role on new dashboard route.

  * API: Revert allowing editors to access GET /datasources.
      Settings: Add ability to override skip_org_role_sync with Env variables.

  * Update to version 9.5.3:

  * CVE-2023-2801: Query: Prevent crash while executing concurrent mixed queries
      (bsc#1212099)

  * CVE-2023-2183: Alerting: Require alert.notifications:write permissions to
      test receivers and templates (bsc#1212100)

  * Update to version 9.5.2: Alerting: Scheduler use rule fingerprint instead of
      version. Explore: Update table min height. DataLinks: Encoded URL fixed.
      TimeSeries: Fix leading null-fill for missing intervals. Dashboard: Revert
      fixed header shown on mobile devices in the new panel header. PostgreSQL:
      Fix TLS certificate issue by downgrading lib/pq. Provisioning: Fix
      provisioning issues with legacy alerting and data source permissions.
      Alerting: Fix misleading status code in provisioning API. Loki: Fix log
      samples using `instant` queries. Panel Header: Implement new Panel Header on
      Angular Panels. Azure Monitor: Fix bug that was not showing resources for
      certain locations. Alerting: Fix panic when reparenting receivers to groups
      following an attempted rename via Provisioning. Cloudwatch Logs: Clarify
      Cloudwatch Logs Limits.

  * Update to 9.5.1 Loki Variable Query Editor: Fix bug when the query is
      updated Expressions: Fix expression load with legacy UID -100

  ##");

  script_tag(name:"affected", value:"'SUSE Manager Client Tools' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"grafana-debuginfo", rpm:"grafana-debuginfo~9.5.5~150200.3.44.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grafana", rpm:"grafana~9.5.5~150200.3.44.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grafana-debuginfo", rpm:"grafana-debuginfo~9.5.5~150200.3.44.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grafana", rpm:"grafana~9.5.5~150200.3.44.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"grafana-debuginfo", rpm:"grafana-debuginfo~9.5.5~150200.3.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grafana", rpm:"grafana~9.5.5~150200.3.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grafana-debuginfo", rpm:"grafana-debuginfo~9.5.5~150200.3.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grafana", rpm:"grafana~9.5.5~150200.3.44.1", rls:"openSUSELeap15.5"))) {
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

# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.1037.1");
  script_cve_id("CVE-2025-3415", "CVE-2025-68156", "CVE-2026-21720", "CVE-2026-21721", "CVE-2026-21722");
  script_tag(name:"creation_date", value:"2026-03-27 04:48:51 +0000 (Fri, 27 Mar 2026)");
  script_version("2026-03-27T06:06:36+0000");
  script_tag(name:"last_modification", value:"2026-03-27 06:06:36 +0000 (Fri, 27 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:1037-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1037-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261037-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245302");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258136");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024905.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grafana' package(s) announced via the SUSE-SU-2026:1037-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for grafana fixes the following issues:

- Security issues fixed:

 - CVE-2026-21722: Public dashboards annotations: use dashboard timerange if time selection disabled (bsc#1258136)
 - CVE-2026-21721: Fixed access control by the dashboard permissions API (bsc#1257337)
 - CVE-2026-21720: Fixed unauthenticated DoS (bsc#1257349)
 - CVE-2025-68156: Fixed potential DoS via unbounded recursion in builtin functions (bsc#1255340)
 - CVE-2025-3415: Fixed exposure of DingDing alerting integration URL to Viewer level users (bsc#1245302)

- Version update from 11.5.10 to 11.6.11 with the following highlighted changes and fixes:

 - Performance Boost: Introduced WebGL-powered geomaps for smoother map visualizations and
 removed blurred backgrounds from UI overlays to speed up the interface.
 - One-Click Actions: Visualizations now support faster navigation via one-click links and actions.
 - Alerting History: Added version history for alert rules, allowing you to track changes over time.
 - Service Accounts: Automated the migration of old API keys to more secure Service Accounts upon startup.
 - Cron Support: Annotations now support Cron syntax for more flexible scheduling.
 - Identity and Auth: Hardened the Avatar feature (now requires sign-in) and fixed several login redirection issues
 when Grafana is hosted on a subpath.
 - Data Source Support: Added support for Cloud Partner Prometheus data sources and improved Azure legend formatting.
 - Alerting Limits: Added size limits for expanded notification templates to prevent system strain.
 - RBAC: Integrated Role-Based Access Control (RBAC) into the Alertmanager via the reqAction field.
 - Data Consistency: Fixed several issues with Graphite and InfluxDB regarding how variables are handled in repeated
 rows or nested queries.
 - Dashboard Reliability: Resolved bugs involving row repeats and 'self-referencing' data links.
 - Alerting Fixes: Patched a critical 'panic' (crash) caused by a race condition in alert rules and fixed issues where
 contact points weren't working correctly.
 - URL Handling: Fixed a bug where 'true' values in URL parameters weren't being read correctly");

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

  if(!isnull(res = isrpmvuln(pkg:"grafana", rpm:"grafana~11.6.11~150200.3.83.1", rls:"openSUSELeap15.6"))) {
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

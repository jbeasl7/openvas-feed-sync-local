# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856257");
  script_cve_id("CVE-2023-6152", "CVE-2024-1313");
  script_tag(name:"creation_date", value:"2024-06-29 04:03:09 +0000 (Sat, 29 Jun 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-21 18:35:59 +0000 (Mon, 21 Oct 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:1530-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1530-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241530-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222155");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-June/035719.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grafana and mybatis' package(s) announced via the SUSE-SU-2024:1530-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for grafana and mybatis fixes the following issues:

grafana was updated to version 9.5.18:

- Grafana now requires Go 1.20
- Security issues fixed:

 * CVE-2024-1313: Require same organisation when deleting snapshots (bsc#1222155)
 * CVE-2023-6152: Add email verification when updating user email (bsc#1219912)

- Other non-security related changes:

 * Version 9.5.17:

 + [FEATURE] Alerting: Backport use Alertmanager API v2

 * Version 9.5.16:

 + [BUGFIX] Annotations: Split cleanup into separate queries and
 deletes to avoid deadlocks on MySQL

 * Version 9.5.15:

 + [FEATURE] Alerting: Attempt to retry retryable errors

 * Version 9.5.14:

 + [BUGFIX] Alerting: Fix state manager to not keep
 datasource_uid and ref_id labels in state after Error
 + [BUGFIX] Transformations: Config overrides being lost when
 config from query transform is applied
 + [BUGFIX] LDAP: Fix enable users on successfull login

 * Version 9.5.13:

 + [BUGFIX] BrowseDashboards: Only remember the most recent
 expanded folder
 + [BUGFIX] Licensing: Pass func to update env variables when
 starting plugin

 * Version 9.5.12:

 + [FEATURE] Azure: Add support for Workload Identity
 authentication

 * Version 9.5.9:

 + [FEATURE] SSE: Fix DSNode to not panic when response has empty
 response
 + [FEATURE] Prometheus: Handle the response with different field
 key order
 + [BUGFIX] LDAP: Fix user disabling


mybatis:

- `apache-commons-ognl` is now a non-optional dependency
- Fixed building with log4j v1 and v2 dependencies");

  script_tag(name:"affected", value:"'grafana and mybatis' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"grafana", rpm:"grafana~9.5.18~150200.3.56.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mybatis", rpm:"mybatis~3.5.6~150200.5.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mybatis-javadoc", rpm:"mybatis-javadoc~3.5.6~150200.5.6.1", rls:"openSUSELeap15.6"))) {
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

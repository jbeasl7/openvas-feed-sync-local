# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.0545.1");
  script_cve_id("CVE-2023-3128", "CVE-2023-6152", "CVE-2024-45337", "CVE-2024-6837", "CVE-2024-8118");
  script_tag(name:"creation_date", value:"2025-02-18 11:01:57 +0000 (Tue, 18 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-30 17:49:02 +0000 (Fri, 30 Jun 2023)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0545-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0545-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250545-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231024");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234554");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236301");
  script_xref(name:"URL", value:"https://grafana.com/docs/grafana/next/breaking-changes/breaking-changes-v10-0");
  script_xref(name:"URL", value:"https://grafana.com/docs/grafana/next/breaking-changes/breaking-changes-v10-3/");
  script_xref(name:"URL", value:"https://grafana.com/docs/grafana/next/whatsnew/whats-new-in-v10-0/");
  script_xref(name:"URL", value:"https://grafana.com/docs/grafana/next/whatsnew/whats-new-in-v10-1/");
  script_xref(name:"URL", value:"https://grafana.com/docs/grafana/next/whatsnew/whats-new-in-v10-2/");
  script_xref(name:"URL", value:"https://grafana.com/docs/grafana/next/whatsnew/whats-new-in-v10-3/");
  script_xref(name:"URL", value:"https://grafana.com/docs/grafana/next/whatsnew/whats-new-in-v10-4/");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-February/020341.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grafana' package(s) announced via the SUSE-SU-2025:0545-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for grafana fixes the following issues:

grafana was updated from version 9.5.18 to 10.4.13 (jsc#PED-11591,jsc#PED-11649):

- Security issues fixed:
 * CVE-2024-45337: Prevent possible misuse of ServerConfig.PublicKeyCallback by upgrading
 golang.org/x/crypto (bsc#1234554)
 * CVE-2023-3128: Fixed authentication bypass using Azure AD OAuth (bsc#1212641)
 * CVE-2023-6152: Add email verification when updating user email (bsc#1219912)
 * CVE-2024-6837: Fixed potential data source permission escalation (bsc#1236301)
 * CVE-2024-8118: Fixed permission on external alerting rule write endpoint (bsc#1231024)

- Potential breaking changes in version 10:
 * In panels using the `extract fields` transformation, where one
 of the extracted names collides with one of the already
 existing ields, the extracted field will be renamed.
 * For the existing backend mode users who have table
 visualization might see some inconsistencies on their panels.
 We have updated the table column naming. This will
 potentially affect field transformations and/or field
 overrides. To resolve this either: update transformation or
 field override.
 * For the existing backend mode users who have Transformations
 with the `time` field, might see their transformations are
 not working. Those panels that have broken transformations
 will fail to render. This is because we changed the field
 key. To resolve this either: Remove the affected panel and
 re-create it, Select the `Time` field again, Edit the `time`
 field as `Time` for transformation in `panel.json` or
 `dashboard.json`
 * The following data source permission endpoints have been removed:
 `GET /datasources/:datasourceId/permissions`
 `POST /api/datasources/:datasourceId/permissions`
 `DELETE /datasources/:datasourceId/permissions`
 `POST /datasources/:datasourceId/enable-permissions`
 `POST /datasources/:datasourceId/disable-permissions`
 + Please use the following endpoints instead:
 `GET /api/access-control/datasources/:uid` for listing data
 source permissions
 `POST /api/access-control/datasources/:uid/users/:id`,
 `POST /api/access-control/datasources/:uid/teams/:id` and
 `POST /api/access-control/datasources/:uid/buildInRoles/:id`
 for adding or removing data source permissions
 * If you are using Terraform Grafana provider to manage data source permissions, you will need to upgrade your
 provider.
 * For the existing backend mode users who have table visualization might see some inconsistencies on their panels.
 We have updated the table column naming. This will potentially affect field transformations and/or field overrides.
 * The deprecated `/playlists/{uid}/dashboards` API endpoint has been removed.
 Dashboard information can be retrieved from the `/dashboard/...` APIs.
 * The `PUT /api/folders/:uid` endpoint no more supports modifying the folder's `UID`
 * Removed all components for the old panel header design.
 * Please ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"grafana", rpm:"grafana~10.4.13~150200.3.59.1", rls:"openSUSELeap15.6"))) {
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

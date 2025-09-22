# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833803");
  script_cve_id("CVE-2023-40577");
  script_tag(name:"creation_date", value:"2024-03-04 12:50:29 +0000 (Mon, 04 Mar 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-31 14:45:39 +0000 (Thu, 31 Aug 2023)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:0512-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0512-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240512-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218838");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-February/017925.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-prometheus-alertmanager' package(s) announced via the SUSE-SU-2024:0512-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"+ CVE-2023-40577: Fix stored XSS via the /api/v1/alerts endpoint in the Alertmanager UI (bsc#1218838)
 * Other changes and bugs fixed:
 + Configuration: Fix empty list of receivers and inhibit_rules would cause the alertmanager to crash
 + Templating: Fixed a race condition when using the title function. It is now race-safe
 + API: Fixed duplicate receiver names in the api/v2/receivers API endpoint
 + API: Attempting to delete a silence now returns the correct status code, 404 instead of 500
 + Clustering: Fixes a panic when tls_client_config is empty
 + Webhook: url is now marked as a secret. It will no longer show up in the logs as clear-text
 + Metrics: New label reason for alertmanager_notifications_failed_total metric to indicate the type of error of the
 alert delivery
 + Clustering: New flag --cluster.label, to help to block any traffic that is not meant for the cluster
 + Integrations: Add Microsoft Teams as a supported integration
- Version 0.25.0:
 * Fail configuration loading if api_key and api_key_file are defined at the same time
 * Fix the alertmanager_alerts metric to avoid counting resolved alerts as active. Also added a new
 alertmanager_marked_alerts metric that retain the old behavior
 * Trim contents of Slack API URLs when reading from files
 * amtool: Avoid panic when the label value matcher is empty
 * Fail configuration loading if api_url is empty for OpsGenie
 * Fix email template for resolved notifications
 * Add proxy_url support for OAuth2 in HTTP client configuration
 * Reload TLS certificate and key from disk when updated
 * Add Discord integration
 * Add Webex integration
 * Add min_version support to select the minimum TLS version in HTTP client configuration
 * Add max_version support to select the maximum TLS version in HTTP client configuration
 * Emit warning logs when truncating messages in notifications
 * Support HEAD method for the /-/healty and /-/ready endpoints
 * Add support for reading global and local SMTP passwords from files
 * UI: Add 'Link' button to alerts in list
 * UI: Allow to choose the first day of the week as Sunday or Monday
- Version 0.24.0:
 * Fix HTTP client configuration for the SNS receiver
 * Fix unclosed file descriptor after reading the silences snapshot file
 * Fix field names for mute_time_intervals in JSON marshaling
 * Ensure that the root route doesn't have any matchers
 * Truncate the message's title to 1024 chars to avoid hitting Slack limits
 * Fix the default HTML email template (email.default.html) to match with the canonical source
 * Detect SNS FIFO topic based on the rendered value
 * Avoid deleting and recreating a silence when an update is possible
 * api/v2: Return 200 OK when deleting an expired silence
 * amtool: Fix the silence's end date when adding a silence. The end date is (start date + duration) while it used to
 be (current time + duration). The new behavior is consistent with the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'golang-github-prometheus-alertmanager' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-alertmanager", rpm:"golang-github-prometheus-alertmanager~0.26.0~150100.4.19.1", rls:"openSUSELeap15.5"))) {
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

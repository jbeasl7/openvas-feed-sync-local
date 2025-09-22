# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145819");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2021-04-26 04:53:09 +0000 (Mon, 26 Apr 2021)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-22 20:14:00 +0000 (Thu, 22 Apr 2021)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2021-31545", "CVE-2021-31546", "CVE-2021-31547", "CVE-2021-31548", "CVE-2021-31549",
                "CVE-2021-31550", "CVE-2021-31551", "CVE-2021-31552", "CVE-2021-31553", "CVE-2021-31554",
                "CVE-2021-31555");

  script_name("MediaWiki <= 1.36.0 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-31545: The page_recent_contributors in the AbuseFilter extension leaks the existence of
    certain deleted MediaWiki usernames, related to rev_deleted.

  - CVE-2021-31546: The AbuseFilter extension incorrectly logs sensitive suppression deletions,
    which should not have been visible to users with access to view AbuseFilter log data.

  - CVE-2021-31547: AbuseFilterCheckMatch API from the AbuseFilter extension reveals suppressed edits and
    usernames to unprivileged users through the iteration of crafted AbuseFilter rules.

  - CVE-2021-31548: A MediaWiki user who is partially blocked or was unsuccessfully blocked could bypass
    AbuseFilter and have their edits completed.

  - CVE-2021-31549: The Special:AbuseFilter/examine form allows for the disclosure of suppressed MediaWiki
    usernames to unprivileged users.

  - CVE-2021-31550: Via crafted configuration variables, a malicious actor could introduce XSS payloads
    into various layers of the CommentBox extension.

  - CVE-2021-31551: Crafted payloads for Token-related query parameters allow for XSS on certain
    PageForms-managed MediaWiki pages.

  - CVE-2021-31552: The AbuseFilter extension incorrectly executes certain rules related to blocking
    accounts after account creation. Such rules allow for user accounts to be created while blocking
    only the IP address used to create an account (and not the user account itself). Such rules could
    also be used by a nefarious, unprivileged user to catalog and enumerate any number of IP addresses
    related to these account creations.

  - CVE-2021-31553: MediaWiki usernames with trailing whitespace could be stored in the cu_log database
    table such that denial of service occurred for certain CheckUser extension pages and functionality.
    For example, the attacker could turn off Special:CheckUserLog and thus interfere with usage tracking.

  - CVE-2021-31554: The AbuseFilter extension improperly handles account blocks for certain automatically
    created MediaWiki user accounts, thus allowing nefarious users to remain unblocked.

  - CVE-2021-31555: The Oauth extension does not validate the oarc_version (aka
    oauth_registered_consumer.oarc_version) parameter's length.");

  script_tag(name:"affected", value:"MediaWiki prior to version 1.36.0.");

  script_tag(name:"solution", value:"Update to version 1.36.0 or later.");

  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T71367");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T71617");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T223654");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T272333");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T274152");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T270767");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T259433");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T152394");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T275669");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T272244");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T277388");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version: version, test_version: "1.36.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.36.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

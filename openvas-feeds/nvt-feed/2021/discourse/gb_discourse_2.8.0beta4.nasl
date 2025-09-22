# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146397");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2021-07-29 07:24:02 +0000 (Thu, 29 Jul 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-01 16:58:00 +0000 (Wed, 01 Sep 2021)");

  script_cve_id("CVE-2021-32788", "CVE-2021-39161");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse 2.8.0.beta4 Security Update");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_http_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"A new Discourse update includes two security fixes.");

  script_tag(name:"insight", value:"The following flaw exists / The following security
  fix is included:

  - CVE-2021-32788: There are two bugs which led to the post creator of a whisper post being
  revealed to non-staff users. Staff users that creates a whisper post in a personal message is
  revealed to non-staff participants of the personal message even though the whisper post cannot
  be seen by them. When a whisper post is before the last post in a post stream, deleting the last
  post will result in the creator of the whisper post to be revealed to non-staff users as the last
  poster of the topic.

  - CVE-2021-39161: Category names can be uses for XSS attacks. This vulnerability only affects
  sites which have modified or disabled Discourse's default Content Security Policy and have
  allowed for moderators to modify categories.");

  script_tag(name:"affected", value:"Discourse version 2.8.0.beta1 through 2.8.0.beta3.");

  script_tag(name:"solution", value:"Update to version 2.8.0.beta4 or later.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://meta.discourse.org/t/2-8-0-beta4-security-release-new-pm-style-and-more/197878");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-v6xg-q577-vc92");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-xhmc-9jwm-wqph");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "2.8.0.beta1", test_version2: "2.8.0.beta3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.8.0.beta4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

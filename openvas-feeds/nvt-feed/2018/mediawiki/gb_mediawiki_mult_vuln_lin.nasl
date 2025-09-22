# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141564");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2018-10-05 09:52:00 +0700 (Fri, 05 Oct 2018)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-18 04:15:00 +0000 (Fri, 18 Oct 2019)");

  script_cve_id("CVE-2018-0503", "CVE-2018-0504", "CVE-2018-0505");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki Multiple Vulnerabilities (Sep 2018) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - $wgRateLimits entry for 'user' overrides 'newbie' (CVE-2018-0503)

  - Redirect/logid can link to the incorrect log and reveal hidden information (CVE-2018-0504)

  - BotPasswords can bypass CentralAuth's account lock (CVE-2018-0505)");

  script_tag(name:"affected", value:"MediaWiki 1.27.x, 1.29.x, 1.30.x, 1.31.x and prior.");

  script_tag(name:"solution", value:"Update to version 1.27.5, 1.29.3, 1.30.1, 1.31.1 or later.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/wikitech-l/2018-September/090849.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.27.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.27.5");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.28", test_version2: "1.29.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.29.3");
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^1\.30\.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.30.1");
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^1\.31\.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.31.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

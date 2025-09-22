# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cleantalk:cleantalk-spam-protect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170982");
  script_version("2025-07-14T05:43:40+0000");
  script_tag(name:"last_modification", value:"2025-07-14 05:43:40 +0000 (Mon, 14 Jul 2025)");
  script_tag(name:"creation_date", value:"2024-11-27 12:46:45 +0000 (Wed, 27 Nov 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-12 00:25:44 +0000 (Sat, 12 Jul 2025)");

  script_cve_id("CVE-2024-10542");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress CleanTalk Plugin < 6.44 Authorization Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/cleantalk-spam-protect/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'CleanTalk' is prone to an
  authorization bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin is vulnerable to unauthorized Arbitrary Plugin
  installation due to an authorization bypass via reverse DNS spoofing on the checkWithoutToken
  function.");

  script_tag(name:"impact", value:"This makes it possible for unauthenticated attackers to install
  and activate arbitrary plugins which can be leveraged to achieve remote code execution if another
  vulnerable plugin is installed and activated.");

  script_tag(name:"affected", value:"WordPress CleanTalk plugin prior to version 6.44.");

  script_tag(name:"solution", value:"Update to version 6.44 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2024/11/200000-wordpress-sites-affected-by-unauthenticated-critical-vulnerabilities-in-anti-spam-by-cleantalk-wordpress-plugin/");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/cleantalk-spam-protect/spam-protection-anti-spam-firewall-by-cleantalk-6432-authorization-bypass-via-reverse-dns-spoofing-to-unauthenticated-arbitrary-plugin-installation");

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

if (version_is_less(version: version, test_version: "6.44")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.44", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

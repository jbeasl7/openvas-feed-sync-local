# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144820");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-10-23 09:22:10 +0000 (Fri, 23 Oct 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-26 20:20:00 +0000 (Mon, 26 Oct 2020)");

  script_cve_id("CVE-2020-15252");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki < 11.10.6, 12.x < 12.5 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"XWiki is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"insight", value:"Any user with SCRIPT right (EDIT right before XWiki 7.4) can gain access to
  the application server Servlet context which contains tools allowing to instantiate arbitrary Java objects and
  invoke methods that may lead to arbitrary code execution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"XWiki prior to version 11.10.6 or 12.5.");

  script_tag(name:"solution", value:"Update to version 11.10.6, 12.5 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-5hv6-mh8q-q9v8");

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

if (version_is_less(version: version, test_version: "11.10.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.10.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^12\." && version_is_less(version: version, test_version: "12.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

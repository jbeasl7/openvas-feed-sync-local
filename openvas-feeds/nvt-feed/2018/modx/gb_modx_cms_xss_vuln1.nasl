# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:modx:revolution";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141542");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2018-10-01 16:49:26 +0700 (Mon, 01 Oct 2018)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-15 18:22:00 +0000 (Thu, 15 Nov 2018)");

  script_cve_id("CVE-2018-17556");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MODX CMS < 2.7.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_modx_cms_http_detect.nasl");
  script_mandatory_keys("modx/cms/detected");

  script_tag(name:"summary", value:"MODX CMS is prone to a stored cross-site scripting (XSS)
  vulnerability via a Create New Media Source action.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"MODX CMS version 2.x through 2.7.0.");

  script_tag(name:"solution", value:"Update to version 2.7.1 or later.");

  script_xref(name:"URL", value:"https://github.com/modxcms/revolution/issues/14094");
  script_xref(name:"URL", value:"https://github.com/modxcms/revolution/pull/14335");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "2.0", test_version_up: "2.7.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.7.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

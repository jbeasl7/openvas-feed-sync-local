# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cybozu:office";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813618");
  script_version("2024-01-10T05:05:17+0000");
  script_cve_id("CVE-2018-0565", "CVE-2018-0566", "CVE-2018-0567");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-06-27 11:07:13 +0530 (Wed, 27 Jun 2018)");
  script_name("Cybozu Office 10.0.0 - 10.8.0 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Cybozu Office is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An operation restriction bypass error in the application 'Bulletin'.

  - A browse restriction bypass error in the application 'Scheduler'.

  - An input validation error in the application 'MultiReport'.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  script and bypass security restrictions.");

  script_tag(name:"affected", value:"Cybozu Office versions 10.0.0 through 10.8.0.");

  script_tag(name:"solution", value:"Update to version 10.8.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN51737843/index.html");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gb_cybozu_products_http_detect.nasl");
  script_mandatory_keys("cybozu/office/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version =~ "^10\." && version_is_less_equal(version:version, test_version:"10.8.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"10.8.1", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

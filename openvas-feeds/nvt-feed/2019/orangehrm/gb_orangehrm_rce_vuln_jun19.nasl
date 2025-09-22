# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:orangehrm:orangehrm";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113416");
  script_version("2024-05-30T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-05-30 05:05:32 +0000 (Thu, 30 May 2024)");
  script_tag(name:"creation_date", value:"2019-06-24 14:48:35 +0000 (Mon, 24 Jun 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-12839");

  script_name("OrangeHRM <= 4.3.1 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_orangehrm_http_detect.nasl");
  script_mandatory_keys("orangehrm/detected");

  script_tag(name:"summary", value:"OrangeHRM is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists due to an input validation error within
  admin/listMailConfiguration (txtSendmailPath parameter).");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to
  execute arbitrary code on the target machine.");

  script_tag(name:"affected", value:"OrangeHRM through version 4.3.1.");

  script_tag(name:"solution", value:"Update to version 4.3.2 or later.");

  script_xref(name:"URL", value:"https://github.com/orangehrm/orangehrm/releases/tag/4.3.2");
  script_xref(name:"URL", value:"https://ctrsec.io/research/2019/06/12/ace-orangehrm.html");
  script_xref(name:"URL", value:"https://github.com/orangehrm/orangehrm/pull/528");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"4.3.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"4.3.2", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

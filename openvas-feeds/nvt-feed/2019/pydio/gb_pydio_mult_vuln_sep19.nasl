# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pydio:pydio";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113539");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"creation_date", value:"2019-10-07 11:42:39 +0000 (Mon, 07 Oct 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-20 12:40:00 +0000 (Fri, 20 Sep 2019)");

  script_cve_id("CVE-2019-15032", "CVE-2019-15033");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Pydio Core <= 6.0.8 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_pydio_http_detect.nasl");
  script_mandatory_keys("pydio/detected");

  script_tag(name:"summary", value:"Pydio Core is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Due to mishandling error reporting when a directory allows unauthenticated uploads, an attacker
  can obtain sensitive internal server information.

  - Pydio allows authenticated SSRF during a Remote Link Feature download. An attacker can specify
  an intranet address in the file parameter to index.php when sending a file to a remote server.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to obtain
  sensitive information from the affected server or other servers in the same network.");

  script_tag(name:"affected", value:"Pydio Core version 6.0.8 and prior.");

  script_tag(name:"solution", value:"Update to version 7.0.0 or later.");

  script_xref(name:"URL", value:"https://heitorgouvea.me/2019/09/17/CVE-2019-15032");
  script_xref(name:"URL", value:"https://heitorgouvea.me/2019/09/17/CVE-2019-15033");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "6.0.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.0.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112474");
  script_version("2023-10-13T05:06:09+0000");
  script_cve_id("CVE-2018-1000860", "CVE-2018-1000869", "CVE-2018-1000870", "CVE-2019-1000010");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:09 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2019-01-02 13:50:12 +0100 (Wed, 02 Jan 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-08 21:03:00 +0000 (Tue, 08 Jan 2019)");

  script_name("phpIPAM < 1.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpipam_http_detect.nasl");
  script_mandatory_keys("phpipam/detected");

  script_tag(name:"summary", value:"phpIPAM is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2018-1000860, CVE-2018-1000870, CVE-2019-1000010: Cross-site scripting (XSS)

  - CVE-2018-1000869: Blind SQL injection");

  script_tag(name:"affected", value:"phpIPAM through version 1.3.2.");

  script_tag(name:"solution", value:"Update to phpIPAM 1.4 or later.");

  script_xref(name:"URL", value:"https://github.com/phpipam/phpipam/issues/2338");
  script_xref(name:"URL", value:"https://github.com/phpipam/phpipam/issues/2326");
  script_xref(name:"URL", value:"https://github.com/phpipam/phpipam/issues/2344");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:phpipam:phpipam";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"1.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wftpserver:wing_ftp_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100611");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-04-28 14:05:27 +0200 (Wed, 28 Apr 2010)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("Wing FTP Server < 3.4.1 Multiple Information Disclosure Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_wing_ftp_server_consolidation.nasl");
  script_mandatory_keys("wing_ftp/server/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210121195847/https://www.securityfocus.com/bid/39727/");

  script_tag(name:"summary", value:"Wing FTP Server is prone to multiple information disclosure
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to gain access to
  sensitive information that may lead to further attacks.");

  script_tag(name:"affected", value:"Wing FTP Server versions prior to 3.4.1.");

  script_tag(name:"solution", value:"The vendor released an update. Please see the references for
  more information.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

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

if( version_is_less( version:version, test_version:"3.4.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.4.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

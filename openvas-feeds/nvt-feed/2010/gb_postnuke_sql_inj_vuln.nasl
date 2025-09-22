# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postnuke:postnuke";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800771");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2010-1713");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PostNuke <= 0.764 modload Module 'sid' Parameter SQLi Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_zikula_detect.nasl");
  script_mandatory_keys("postnuke/detected");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58204");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/12410");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39713");

  script_tag(name:"insight", value:"The flaw exists due to failure to sufficiently sanitize user
  supplied data to 'modules.php' via 'sid' parameter before using it in an SQL query.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"PostNuke is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to access,
  modify or delete information in the underlying database.");

  script_tag(name:"affected", value:"PostNuke version 0.764 and prior.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if( version_is_equal( version:vers, test_version:"0.76" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

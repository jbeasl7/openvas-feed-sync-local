# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802806");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2012-02-23 16:21:11 +0530 (Thu, 23 Feb 2012)");
  script_name("Microsoft IIS Default Welcome Page Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_mandatory_keys("IIS/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  sensitive information that could aid in further attacks.");

  script_tag(name:"affected", value:"Microsoft Internet Information Services.");

  script_tag(name:"insight", value:"The flaw is due to misconfiguration of IIS Server, which allows to
  access default pages when the server is not used.");

  script_tag(name:"summary", value:"Microsoft IIS Webserver is prone to an information disclosure vulnerability.");

  script_tag(name:"solution", value:"Disable the default pages within the server configuration.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! iisPort = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( port:iisPort, cpe:CPE, nofork:TRUE ) )
  exit( 0 );

response = http_get_cache(item:"/", port:iisPort);

if(response && (
   (("<title id=titletext>Under Construction</title>" ><response) && ("The site you were trying to reach does not currently have a default page" >< response)) ||
   (("welcome to iis 4.0" >< response) && ("microsoft windows nt 4.0 option pack" >< response)) ||
   (("<title>iis7</title>" >< response) && ('<img src="welcome.png" alt="iis7"' >< response)) ||
   (("<title>IIS7</title>" >< response) && ('<img src="welcome.png" alt="IIS7"' >< response))
  )){
  security_message(port:iisPort);
  exit(0);
}

exit(99);

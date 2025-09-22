# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901024");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-09-22 10:03:41 +0200 (Tue, 22 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-3199");
  script_name("Uebimiau Webmail Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9493");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/52724");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_uebimiau_webmail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("uebimiau/webmail/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to gain sensitive information
  in the context of the affected web application.");

  script_tag(name:"affected", value:"Uebimiau Webmail version 3.2.0-2.0");

  script_tag(name:"insight", value:"Error is due to an improper sanitization of user supplied input in
  the 'system_admin/admin.ucf' file.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Uebimiau Webmail is prone to an information disclosure vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

uwebPort = http_get_port(default:80);

uwebVer = get_kb_item("www/" + uwebPort + "/Uebimiau/Webmail");
if(!uwebVer){
  exit(0);
}

uwebVer = eregmatch(pattern:"^(.+) under (/.*)$", string:uwebVer);

if((!safe_checks()) && (uwebVer[2] != NULL))
{
  request = http_get(item:string(uwebVer[2] + "/inc/database/system_admin"+
                                             "/admin.ucf"), port:uwebPort);
  response = http_send_recv(port:uwebPort, data:request);

  if(eregmatch(pattern:":[a-z0-9]{32,32}", string:response) &&
     egrep(pattern:"^HTTP/1\.[01] 200", string:response))
  {
    security_message(uwebPort);
    exit(0);
  }
}

if(uwebVer[1] != NULL)
{
  if(version_is_equal(version:uwebVer[1], test_version:"3.2.0.2.0")){
    security_message(uwebPort);
  }
}

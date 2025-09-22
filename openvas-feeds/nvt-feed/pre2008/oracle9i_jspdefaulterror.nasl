# SPDX-FileCopyrightText: 2003 Javier Fernandez-Sanguino
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11226");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2001-1372");
  script_name("Oracle 9iAS default error information disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Javier Fernandez-Sanguino");
  script_family("Web application abuses");
  script_dependencies("gb_oracle_app_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("oracle/http_server/detected");

  script_tag(name:"summary", value:"Oracle 9iAS allows remote attackers to obtain the physical path of a file
  under the server root via a request for a non-existent .JSP file. The default
  error generated leaks the pathname in an error message.");

  script_tag(name:"solution", value:"Ensure that virtual paths of URL is different from the actual directory
  path. Also, do not use the <servletzonepath> directory in
  'ApJServMount <servletzonepath> <servletzone>' to store data or files.

  Upgrading to Oracle 9iAS 1.1.2.0.0 will also fix this issue.");

  script_xref(name:"URL", value:"http://www.nextgenss.com/papers/hpoas.pdf");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3341");
  script_xref(name:"URL", value:"http://otn.oracle.com/deploy/security/pdf/jspexecute_alert.pdf");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/278971");
  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-2002-08.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

# Make a request for the configuration file
errorjsp = "/nonexistent.jsp";
req = http_get(item:errorjsp, port:port);
res = http_send_recv(data:req, port:port);
if(!res)
  exit(0);

location = egrep(pattern:"java.io.FileNotFoundException", string:res);
if(location)  {
  # Thanks to Paul Johnston for the tip that made the following line
  # work (jfs)
  # MA 2005-02-13: This did not work on Windows where / is replaced by \
  path = ereg_replace(pattern:strcat("(java.io.FileNotFoundException: )(.*[^/\])[/\]+",substr(errorjsp, 1),".*"), replace:"\2", string:location);
  security_message(port:port, data:string("The web root physical is ", path ));
  exit(0);
}

exit(99);

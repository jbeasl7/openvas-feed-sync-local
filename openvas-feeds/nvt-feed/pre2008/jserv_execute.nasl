# SPDX-FileCopyrightText: 2002 Michael Scheidell
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10925");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0307");
  script_name("Oracle Jserv Executes outside of doc_root");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Michael Scheidell");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("apache/jserv/banner");

  script_tag(name:"solution", value:"Upgrade to OJSP Release 1.1.2.0.0, available on Oracle
  Technology Network's OJSP web site.");

  script_tag(name:"summary", value:"Detects Vulnerability in the execution of JSPs outside
  doc_root.");

  script_tag(name:"insight", value:"A potential security vulnerability has been discovered in
  Oracle JSP releases 1.0.x through 1.1.1 (in Apache/Jserv). This vulnerability permits access
  to and execution of unintended JSP files outside the doc_root in Apache/Jserv. For example,
  accessing:

  http://www.example.com/a.jsp//..//..//..//..//..//../b.jsp

  will execute b.jsp outside the doc_root instead of a.jsp if there is a b.jsp file in the
  matching directory.

  Further, Jserv Releases 1.0.x - 1.0.2 have additional vulnerability:

  Due to a bug in Apache/Jserv path translation, any URL that looks like:

  http://example.com:port/servlets/a.jsp,

  makes Oracle JSP execute 'd:\servlets\a.jsp' if such a directory path actually exists. Thus,
  a URL virtual path, an actual directory path and the Oracle JSP name (when using Oracle Apache/JServ)
  must match for this potential vulnerability to occur.");

  script_tag(name:"affected", value:"Oracle8i Release 8.1.7, iAS Release version 1.0.2

  Oracle JSP, Apache/JServ Releases version 1.0.x - 1.1.1");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
banner = http_get_remote_headers(port:port);
if(!banner)
  exit(0);

# Server: Apache/1.3.34 (Unix) mod_tsunami/3.0 mod_jk/1.2.15 mod_fastcgi/2.4.2 ApacheJServ/1.1.2 FrontPage/5.0.2.2510
# Server: apachejserv/1.0.1
if(ereg(pattern:".*apachejserv/1\.(0|1\.[01][^0-9])", string:banner, icase:TRUE)) {
  security_message(port:port);
  exit(0);
}

exit(99);

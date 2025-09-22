# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803958");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2013-6348");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2013-10-29 15:36:50 +0530 (Tue, 29 Oct 2013)");
  script_name("Apache Struts 2.x <= 2.3.15.3 XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/struts/http/detected");

  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/struts-23153-cross-site-scripting");
  script_xref(name:"URL", value:"http://www.securityhome.eu/exploits/exploit.php?eid=156451617526e27dd866c97.43571723");

  script_tag(name:"summary", value:"Apache Struts is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the
  response.");

  script_tag(name:"insight", value:"An error exists in the application which fails to
  properly sanitize user-supplied input to 'namespace' parameter before using it.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers
  to steal the victim's cookie-based authentication credentials.");

  script_tag(name:"affected", value:"Apache Struts 2.x through 2.3.15.3.");

  script_tag(name:"solution", value:"No known solution was made available for at least one
  year since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_analysis");
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

dir += "/struts2-showcase";

res = http_get_cache(item:dir + "/showcase.action", port:port);
if(res && "The Apache Software Foundation" >< res && "Showcase<" >< res && "struts" >< res) {

  url = dir + "/config-browser/actionNames.action?namespace=<script>alert(document.cookie);</script>";

  if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"<script>alert\(document\.cookie\);</script>")) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);

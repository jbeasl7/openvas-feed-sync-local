# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805070");
  script_version("2023-07-06T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-06 05:05:36 +0000 (Thu, 06 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-06-17 11:22:32 +0530 (Wed, 17 Jun 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Apexis IP CAM Information Disclosure Vulnerability (Jun 2016) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Apexis IP Cameras are prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to the camera is not restricting some files
  which are containing sensitive information.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to gain access to
  potentially sensitive information.");

  script_tag(name:"affected", value:"Apexis IP CAM models APM-H602-MPC, APM-H803-MPC,
  APM-H901-MPC, APM-H501-MPC, APM-H403-MPC and APM-H804.");

  script_tag(name:"solution", value:"As a workaround apply appropriate firewall rules.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37298");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132213");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

foreach dir (make_list_unique("/", "/cgi-bin", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/get_status.cgi");
  if (res !~ "^HTTP/1\.[01] 200" || "ret_prot_mode='APM-H" >!< res)
    continue;

  url = dir + "/get_tutk_account.cgi";

  if (http_vuln_check(port: port, url: url, check_header: TRUE, pattern: "ret_tutk_user=",
                      extra_check: "ret_tutk_pwd=")) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

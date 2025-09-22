# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806058");
  script_version("2023-06-28T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-28 05:05:21 +0000 (Wed, 28 Jun 2023)");
  script_tag(name:"creation_date", value:"2015-09-22 15:57:38 +0530 (Tue, 22 Sep 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("ADH-Web Server IP-Cameras Multiple Improper Access Restrictions Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"ADH-Web Server IP-Camera is prone to multiple access
  restrictions vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws are due to an:

  - Insufficient validation of user supplied input via 'variable' in variable.cgi script.

  - Unauthenticated access of all files on the cameras.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain
  access to valuable information such as access credentials, network configuration and other
  sensitive information in plain text.");

  script_tag(name:"affected", value:"ADH-Web Server IP-Cameras, SD Advanced Closed IPTV,
  SD Advanced, EcoSense, Digital Sprite 2.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38245");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/133634");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

res = http_get_cache(port: port, item: "/gui/gui_outer_frame.shtml");

if ("ipCamera" >< res && "Server: ADH-Web" >< res) {
  url = "/variable.cgi?variable=camconfig[0]&slaveip=127.0.0.1";

  if (http_vuln_check(port: port, url: url, check_header: TRUE, pattern: "telm_cam_protocol=",
                      extra_check: make_list("supported_streams=", "aspect_ratio=", "lens_type="))) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

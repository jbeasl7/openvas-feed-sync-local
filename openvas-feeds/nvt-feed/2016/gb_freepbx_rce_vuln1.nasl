# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:freepbx:freepbx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106318");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-09-30 10:47:53 +0700 (Fri, 30 Sep 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FreePBX 13.x RCE Vulnerability - Active Check");

  # nb: No ACT_ATTACK as this seems to be just a standard AJAX call / request e.g. an admin would do
  # via a browser as well.
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_freepbx_http_detect.nasl");
  script_mandatory_keys("freepbx/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"FreePBX is prone to a unauthenticated remote command execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"FreePBX is vulnerable to unauthenticated remote command
  execution in the Hotel Wakeup module.");

  script_tag(name:"impact", value:"An unauthenticated remote attacker may execute arbitrary
  commands.");

  script_tag(name:"affected", value:"FreePBX versions 13.x.");

  script_tag(name:"solution", value:"Update to version 13.0.188.1 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40434/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];

if (version =~ "^13\.") {
  if (version_is_less(version: version, test_version: "13.0.188.1")) {

    dir = infos["location"];
    rep_dir = dir;

    if (dir == "/")
      dir = "";

    url = dir + "/admin/ajax.php";

    data = "module=hotelwakeup&command=savecall";

    req = http_post_put_req(port: port, url: url, data: data, referer_url: "/");
    res = http_keepalive_send_recv(port: port, data: req);

    if ("Referrer" >< res) {
      report = http_report_vuln_url(port: port, url: url);
      report += '\n\n' + report_fixed_ver(installed_version: version, fixed_version: "13.0.188.1", install_url: rep_dir);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);

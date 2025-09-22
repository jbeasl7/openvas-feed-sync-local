# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-645_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803730");
  script_version("2025-01-24T15:39:34+0000");
  script_tag(name:"last_modification", value:"2025-01-24 15:39:34 +0000 (Fri, 24 Jan 2025)");
  script_tag(name:"creation_date", value:"2013-08-05 15:17:38 +0530 (Mon, 05 Aug 2013)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2013-7389");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DIR-645 Router Multiple Vulnerabilities (Aug 2013) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/http/detected");
  script_require_ports("Services/www", 8080);

  script_tag(name:"summary", value:"D-Link DIR-645 Router is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Buffer overflow in post_login.xml, hedwig.cgi and authentication.cgi when handling specially
  crafted requests.

  - Input passed to the 'deviceid' parameter in bind.php, 'RESULT' parameter in info.php and
  'receiver' parameter in bsc_sms_send.php is not properly sanitised before being returned to the
  user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause denial of
  service or execute arbitrary HTML and script code in a user's browser session in context of an
  affected website.");

  script_tag(name:"affected", value:"D-Link DIR-645 firmware version 1.04 and prior.");

  script_tag(name:"solution", value:"Update to version 1.04B11 or later.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Aug/17");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61579");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/27283");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Aug/17");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122659");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/527705");
  script_xref(name:"URL", value:"http://roberto.greyhats.it/advisories/20130801-dlink-dir645.txt");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/hardware/d-link-dir-645-103b08-multiple-vulnerabilities");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = '/parentalcontrols/bind.php?deviceid="><script>alert(document.cookie)</script><';

if (http_vuln_check(port: port, url: url, check_header: TRUE,
                    pattern: "><script>alert\(document\.cookie\)</script><",
                    extra_check: make_list("OpenDNS", "overriteDeviceID"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

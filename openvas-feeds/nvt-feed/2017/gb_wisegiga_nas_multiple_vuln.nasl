# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:wisegiga:nas";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811336");
  script_version("2025-03-26T05:38:58+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-26 05:38:58 +0000 (Wed, 26 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-09-12 13:20:40 +0530 (Tue, 12 Sep 2017)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("WiseGiga NAS Multiple Vulnerabilities (Sep 2017) - Active Check");

  script_tag(name:"summary", value:"WiseGiga NAS devices are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP POST with
  default credentials and check whether it is able to login or not.");

  script_tag(name:"insight", value:"The following flaws exist:

  - An user controlled input is not sufficiently sanitized and can be exploit
    by an attacker to get sensitive information.

  - By sending GET request to the following URI's with 'filename=' as a
    parameter, an attacker can trigger the vulnerabilities:

  - /webfolder/download_file1.php

  - down_data.php

  - download_file.php

  - mobile/download_file1.php

  - By sending GET request to '/mobile/download_file2.php' an attacker can get
    sensitive information.

  - By sending a GET request to 'root_exec_cmd()' with user controlled '$cmd'
    variable input an attacker can execute arbitrary commands.

  - Accessing 'webfolder/config/config.php' will disclose the PHP configuration.

  - A default account exists: Username: guest, Password: guest09#$");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to bypass authentication mechanism and perform
  unauthorized actions and execute arbitrary commands.");

  script_tag(name:"affected", value:"WiseGiga NAS devices in all versions.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42651");
  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3402");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wisegiga_nas_detect.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("WiseGiga_NAS/detected");
  script_require_ports("Services/www", 80);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("http_func.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

url = "/webfolder/login_check.php";
postdata = "id=guest&passwd=guest09%23%24&remember_check=0&sel_lang=en: undefined";

req = http_post_put_req(port:port, url:url, data:postdata,
                        accept_header:"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        add_headers:make_array("Content-Type", "application/x-www-form-urlencoded",
                                               "Upgrade-Insecure-Requests", "1"));
res = http_send_recv( port:port, data:req );

if(res =~ "^HTTP/1\.[01] 200" && "location.href='main.php';" >< res &&
   '<script language="JavaScript">' >< res &&
   "Set-Cookie: PASSWORD=guest" >< res && "Set-Cookie: org_name=guest" >< res) {
  report = "It was possible to log in with the default username/password: 'guest/guest09#$'";
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

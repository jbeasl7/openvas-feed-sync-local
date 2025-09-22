# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807055");
  script_version("2023-10-17T05:05:34+0000");
  script_cve_id("CVE-2015-8669");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-07 18:29:00 +0000 (Wed, 07 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-02-02 12:01:15 +0530 (Tue, 02 Feb 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("phpMyAdmin Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"phpMyAdmin is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to obtain sensitive information or not.");

  script_tag(name:"insight", value:"The flaw is due to recommended setting of
  the PHP configuration directive display_errors is set to on, which is against
  the recommendations given in the PHP manual for a production server.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information about the server.");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.0.x prior to 4.0.10.12,
  4.4.x prior to 4.4.15.2 and 4.5.x prior to 4.5.3.1");

  script_tag(name:"solution", value:"Upgrade to phpMyAdmin version 4.0.10.12 or
  4.4.15.2 or 4.5.3.1 or later or apply the patch from the linked references.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2015-6");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/79691");
  script_xref(name:"URL", value:"https://github.com/phpmyadmin/phpmyadmin/commit/c4d649325b25139d7c097e56e2e46cc7187fae45");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl");
  script_mandatory_keys("phpMyAdmin/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + '/libraries/config/messages.inc.php';

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"Fatal error.*PMA_fatalError.*messages.inc.php"))
{
  report = http_report_vuln_url( port:http_port, url:url );
  security_message(port:http_port, data:report);
  exit(0);
}

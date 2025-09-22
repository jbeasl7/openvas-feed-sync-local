# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:dlink";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812376");
  script_version("2025-07-02T05:41:52+0000");
  script_tag(name:"last_modification", value:"2025-07-02 05:41:52 +0000 (Wed, 02 Jul 2025)");
  script_tag(name:"creation_date", value:"2018-01-03 15:39:16 +0530 (Wed, 03 Jan 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DSL-6850U Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  # nb: Experiences in the past have shown that various different devices might be affected
  script_dependencies("gb_dlink_dsl_consolidation.nasl", "gb_dlink_dap_consolidation.nasl",
                      "gb_dlink_dir_consolidation.nasl", "gb_dlink_dwr_consolidation.nasl",
                      "gb_default_credentials_options.nasl");
  script_mandatory_keys("d-link/http/detected");
  script_require_ports("Services/www", 80);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3588");

  script_tag(name:"summary", value:"D-Link DSL-6850U routers are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send the crafted HTTP GET request and check whether it is
  possible to access the administration GUI or not.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Default account 'support' with password 'support' which cannot be disabled.

  - Availability of the shell interface although only a set of commands, but commands can be combined
  using logical AND, logical OR.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to access
  administration of the device and execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"D-Link DSL-6850U versions BZ_1.00.01 - BZ_1.00.09.
  Other devices, models or versions might be also affected.");

  script_tag(name:"solution", value:"Apply the latest security patches from the vendor.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

# If optimize_test = no
if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www" ) )
  exit( 0 );

port = infos["port"];
CPE = infos["cpe"];

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/lainterface.html";
res = http_get_cache( item:url, port:port );
if( ! res || res !~ "^HTTP/1\.[01] 401" )
  exit( 0 );

host = http_host_name( port:port );

# Base64(support:support) == c3VwcG9ydDpzdXBwb3J0
req = string( "GET ", url, " HTTP/1.1\r\n",
              "Host: ", host, "\r\n",
              "Authorization: Basic c3VwcG9ydDpzdXBwb3J0\r\n",
              "\r\n" );
res = http_keepalive_send_recv( port:port, data:req );

if( res && "WAN SETTINGS" >< res && "value='3G Interface" >< res && "menu.html" >< res &&
    "TabHeader=th_setup" >< res && 'src="util.js"' >< res && 'src="language_en.js"' >< res ) {
  report = "It was possible to login with the default account 'support:support' at the following URL: " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

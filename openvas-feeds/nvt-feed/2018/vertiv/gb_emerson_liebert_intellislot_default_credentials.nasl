# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113235");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2018-07-24 13:03:33 +0200 (Tue, 24 Jul 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-13 11:34:00 +0000 (Mon, 13 Sep 2021)");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_cve_id("CVE-2018-12922");

  script_name("Emerson Liebert IntelliSlot Devices Default Credentials (HTTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("gb_emerson_liebert_intellislot_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("liebert/intellislot/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"Emerson Liebert IntelliSlot devices use known default credentials.");

  script_tag(name:"vuldetect", value:"Tries to login via HTTP using known default credentials.");

  script_tag(name:"insight", value:"The default administrator account is called 'Liebert' and using
  the password 'Liebert'.");

  script_tag(name:"impact", value:"Successful exploitation would give an attecker full
  administrative access over the target device.");

  script_tag(name:"affected", value:"All Emerson Liebert IntelliSlot devices.");

  script_tag(name:"solution", value:"Change the password of the 'Liebert' account.");

  script_xref(name:"URL", value:"https://www.seebug.org/vuldb/ssvid-97372");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

CPE = "cpe:/h:liebert:intellislot";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "misc_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! get_app_location( cpe: CPE, port: port, nofork: TRUE ) )
  exit( 0 );

username = "Liebert";
password = "Liebert";

url = "/config/configUser.htm";
auth_header = make_array( "Authorization", "Basic " + base64( str: username + ":" + password ) );
req = http_get_req( port: port, url: url, add_headers: auth_header );
buf = http_keepalive_send_recv( data: req, port: port );

if( buf =~ "^HTTP/1\.[01] 200" && 'enableObject("passwordAdmin");' >< buf ) {
  report = "It was possible to login using the username '" + username + "' and the password '" + password + "'.";
  report += '\n' + http_report_vuln_url( port: port, url: url );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

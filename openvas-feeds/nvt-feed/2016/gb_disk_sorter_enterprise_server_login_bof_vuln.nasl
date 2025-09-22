# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:disksorter:disksorter_enterprise_web_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810301");
  script_version("2024-03-01T14:37:10+0000");
  script_cve_id("CVE-2017-7230");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-31 01:59:00 +0000 (Fri, 31 Mar 2017)");
  script_tag(name:"creation_date", value:"2016-12-02 17:06:55 +0530 (Fri, 02 Dec 2016)");
  script_name("Disk Sorter Enterprise Server Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_disk_sorter_enterprise_server_detect.nasl");
  script_mandatory_keys("DiskSorter/Enterprise/Server/installed");

  script_xref(name:"URL", value:"http://www.disksorter.com");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41666/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40833/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40458/");

  script_tag(name:"summary", value:"Disk Sorter Enterprise Server is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper handling of
  'Login' and 'GET' requests.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote
  attackers to execute remote code or cause the application to crash, creating
  a denial-of-service condition.");

  script_tag(name:"affected", value:"Disk Sorter Enterprise Server version 9.5.12
  and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"9.5.12" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None Available" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

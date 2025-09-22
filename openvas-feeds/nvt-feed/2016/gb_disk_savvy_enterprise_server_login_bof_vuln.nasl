# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:disksavvy:disksavvy_enterprise";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809486");
  script_version("2025-09-09T14:09:45+0000");
  script_cve_id("CVE-2017-6187");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-13 19:11:00 +0000 (Wed, 13 Mar 2019)");
  script_tag(name:"creation_date", value:"2016-12-02 17:06:55 +0530 (Fri, 02 Dec 2016)");
  script_name("Disk Savvy Enterprise Server <= 9.4.18 Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_disk_savvy_enterprise_server_http_detect.nasl");
  script_mandatory_keys("disk_savvy/enterprise/server/detected");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41436/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41146/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40854/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40834/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40459/");

  script_tag(name:"summary", value:"Disk Savvy Enterprise Server is prone to a buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error when processing
  web requests and can be exploited to cause a buffer overflow via an overly long
  string passed to 'Login' request.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition.");

  script_tag(name:"affected", value:"Disk Savvy Enterprise version 9.4.18 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

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

if( version_is_less_equal( version:vers, test_version:"9.4.18" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );

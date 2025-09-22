# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Info: There is an EOL detection for this product in GSF
# This is due to a change in eFront company policy
# Versions 3.6 and below had a community version
# Starting with Version 5.0, the company started to only cater to Enterprise customers

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113104");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2018-02-06 15:00:00 +0100 (Tue, 06 Feb 2018)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-10 13:46:00 +0000 (Thu, 10 Aug 2017)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-4461", "CVE-2015-4462", "CVE-2015-4463");

  script_name("eFront CMS 3.6.15.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_efront_detect.nasl");
  script_mandatory_keys("efront/detected");

  script_tag(name:"summary", value:"eFront CMS is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:'Vulnerabilities:

Absolute path traversal: Allows remote Professor users to obtain sensitive information via a full pathname in the other parameter.

Unrestricted file upload vulnerability: Allows remote authenticated users to execute arbitrary code by uploading a file from a local URL, then accessing it via a direct request to the file in www/content/lessons/"lesson number"/"directory name".

Unrestricted file upload vulnerability: Allows remote authenticated users to execute arbitrary code by uploading a file with an executable extension prepended to a crafted parameter, then accessing it via a direct request to the file in www/content/lessons/"lesson number"/"directory name"');
  script_tag(name:"affected", value:"eFront CMS through version 3.6.15.4");
  script_tag(name:"solution", value:"Update to eFront CMS version 3.6.15.5 or above");

  script_xref(name:"URL", value:"http://mohankallepalli.blogspot.de/2015/05/eFront-cms-multiple-bugs.html");

  exit(0);
}

CPE = "cpe:/a:efrontlearning:efront";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( port: port, cpe: CPE ) ) exit( 0 );

if( version_is_less( version: version, test_version: "3.6.15.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.6.15.5" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

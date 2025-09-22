# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tortoisesvn:tortoisesvn";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107701");
  script_version("2024-06-28T15:38:46+0000");
  script_cve_id("CVE-2019-14422");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-08-28 17:43:37 +0200 (Wed, 28 Aug 2019)");
  script_name("TortoiseSVN <= 1.12.1 RCE Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tortoise_svn_detect.nasl");
  script_mandatory_keys("tortoisesvn/detected");

  script_xref(name:"URL", value:"https://tortoisesvn.net/Changelog.txt");
  script_xref(name:"URL", value:"https://www.vulnerability-lab.com/get_content.php?id=2188");

  script_tag(name:"summary", value:"TortoiseSVN is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
  arbitrary code to compromise the target system.");

  script_tag(name:"affected", value:"TortoiseSVN through version 1.12.1.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - The URI handler of TortoiseSVN (Tsvncmd:) allows a customised diff operation on Excel workbooks,
    which could be used to open remote workbooks without protection from macro security settings.

  - The `tsvncmd:command:diff?path:[file1]?path2:[file2]` will execute a customised diff on [file1]
    and [file2] based on the file extension. For xls files, it will execute the script `diff-xls.js`
    using wscript, which will open the two files for analysis without any macro security warning.");

  script_tag(name:"solution", value:"Update to version 1.12.2 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"1.12.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.12.2", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

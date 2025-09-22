# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bigtreecms:bigtree_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112265");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-05-02 13:38:22 +0200 (Wed, 02 May 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-07 18:10:00 +0000 (Thu, 07 Jun 2018)");
  script_cve_id("CVE-2018-10574");
  script_name("BigTree CMS <= 4.2.22 Remote Upload & Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_bigtree_detect.nasl");
  script_mandatory_keys("bigtree_cms/detected");

  script_tag(name:"summary", value:"BigTree CMS is prone to a remote upload and code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"site/index.php/admin/trees/add/ in BigTree CMS 4.2.22 and earlier allows remote attackers
  to upload and execute arbitrary PHP code because the BigTreeStorage class in core/inc/bigtree/apis/storage.php does not prevent uploads of .htaccess files.");

  script_tag(name:"affected", value:"BigTree CMS versions through 4.2.22.");

  script_tag(name:"solution", value:"Change the affected storage.php file to disable .htaccess extensions or apply the referenced commit.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"Workaround");

  script_xref(name:"URL", value:"https://github.com/bigtreecms/BigTree-CMS/issues/335");
  script_xref(name:"URL", value:"https://github.com/bigtreecms/BigTree-CMS/commit/609bd17728ee1db0487a42d96028d30537528ae8");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"4.2.22" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See solution details" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );

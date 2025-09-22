# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bigtreecms:bigtree_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108144");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-04-19 07:57:33 +0200 (Wed, 19 Apr 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-17 16:55:00 +0000 (Mon, 17 Apr 2017)");
  script_cve_id("CVE-2017-7695");
  script_name("BigTree CMS < 4.2.17 Unrestricted File Upload Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_bigtree_detect.nasl");
  script_mandatory_keys("bigtree_cms/detected");

  script_xref(name:"URL", value:"http://www.math1as.com/bigtree_upload.txt");
  script_xref(name:"URL", value:"https://github.com/bigtreecms/BigTree-CMS/issues/276");

  script_tag(name:"summary", value:"BigTree CMS is prone to an unrestricted file upload vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"BigTree CMS is prone to a unrestricted file upload vulnerability
  because it fails to sufficiently sanitize user-supplied data. If an attacker uploads an 'xxx.php[space]'
  file, they could bypass a safety check and execute any code.");

  script_tag(name:"affected", value:"BigTree CMS versions prior to 4.2.17.");

  script_tag(name:"solution", value:"Update BigTree CMS to version 4.2.17 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"4.2.17" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.2.17" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

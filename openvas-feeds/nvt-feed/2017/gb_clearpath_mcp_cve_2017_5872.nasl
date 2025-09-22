# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:unisys:clearpath_mcp";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140189");
  script_cve_id("CVE-2017-5872");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2023-10-27T16:11:32+0000");

  script_name("Unisys ClearPath MCP Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96782");
  script_xref(name:"URL", value:"https://public.support.unisys.com/common/public/vulnerability/NVD_Detail_Rpt.aspx?ID=42");

  script_tag(name:"impact", value:"Attackers can exploit this issue to cause a denial-of-service condition.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory for more information.");

  script_tag(name:"summary", value:"Unisys ClearPath MCP is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"affected", value:"ClearPath MCP system running 57.1 (before 57.152) or 58.1 (before 58.142) Networking and at
  least one service offering secured connections via SSL/TLS.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # and at least one service offering secured connections via SSL/TLS.

  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-16 15:20:00 +0000 (Thu, 16 Mar 2017)");
  script_tag(name:"creation_date", value:"2017-03-14 18:08:09 +0100 (Tue, 14 Mar 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_clearpath_mcp_ftp_detect.nasl");
  script_mandatory_keys("unisys/clearpath_mcp/version");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version =~ '^57\\.' )
  fix = '57.152';
else if( version =~ '^58\\.' )
  fix = '58.142';
else
  exit( 99 );

if( version_is_less( version:version, test_version:fix ) )
{
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );


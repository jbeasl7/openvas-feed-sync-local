# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:email_gateway";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105599");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-04-08 11:17:54 +0200 (Fri, 08 Apr 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-19 16:04:00 +0000 (Thu, 19 May 2016)");
  script_cve_id("CVE-2016-3969");
  script_name("McAfee Email Gateway XSS Vulnerability (SB10153)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_mcafee_email_gateway_version.nasl");
  script_mandatory_keys("mcafee_email_gateway/product_version", "mcafee_email_gateway/patches");

  script_xref(name:"URL", value:"https://web.archive.org/web/20161023200600/https://kc.mcafee.com/corporate/index?page=content&id=SB10153");

  script_tag(name:"summary", value:"McAfee Email Gateway is prone to a cross-site scripting (XSS)
  vulnerability in the generation of HTML email alerts using SMTP.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This issue is encountered when File Filtering is enabled with
  the action set to ESERVICES:REPLACE. With this configuration, when an email with an attachment is
  blocked and replaced with an alert, the corresponding alert displays the email attachment `as is`
  without it being XML/HTML escaped.");

  script_tag(name:"solution", value:"Apply the hotfix 7.6.404-3328.101 referenced in the
  advisory.");

  script_tag(name:"affected", value:"McAfee Email Gateway version 7.6.x without hotfix
  7.6.404-3328.101 applied.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");

if( ! version = get_app_version( cpe:CPE ) )
  exit( 0 );

if( ! product = get_kb_item( "mcafee_email_gateway/product_name" ) )
  product = "McAfee Email Gateway";

if( ! patches = get_kb_item( "mcafee_email_gateway/patches" ) )
  exit( 0 );

if( version =~ "^7\.6\." )
  patch = "7.6.404-3328.101";
else
  exit( 99 );

if( patch >< patches )
  exit( 99 );

report = product + " (" + version + ") is missing the patch " + patch;
security_message( port:0, data:report );
exit( 0 );

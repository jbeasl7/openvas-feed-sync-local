# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:email_gateway";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105806");
  script_cve_id("CVE-2016-8005");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_version("2023-07-21T05:05:22+0000");

  script_name("McAfee Email Gateway - Application Protections Bypass");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10161");

  script_tag(name:"vuldetect", value:"Check the installed version and hotfixes");
  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory");

  script_tag(name:"summary", value:"MEG is vulnerable to file attachments
  containing the null character. The scanning mechanism fails to identify the
  file name properly.");
  script_tag(name:"insight", value:"The fix changes the file name processing
  functionality to remove NULL characters from the raw header value before it is
  decoded. This addresses the vulnerability, however, there is still an exploit
  situation because certain mail clients, such as Microsoft Outlook, use a '.' in
  place of the NULL. Hence, a file name of 'test<NUL>vbs' that will now be treated
  as 'testvbs' may be treated as 'test.vbs' by the mail client. In such situations
  you would need to change your File Filter rule from '*.vbs' to just '*vbs' to
  protect against the exploit.");

  script_tag(name:"affected", value:"Email Gateway 7.6");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-30 16:48:00 +0000 (Thu, 30 Mar 2017)");
  script_tag(name:"creation_date", value:"2016-07-12 12:40:26 +0200 (Tue, 12 Jul 2016)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_mcafee_email_gateway_version.nasl");
  script_mandatory_keys("mcafee_email_gateway/product_version", "mcafee_email_gateway/patches");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

product = get_kb_item("mcafee_email_gateway/product_name");
if( ! product ) product = 'McAfee Email Gateway';

if( ! patches = get_kb_item("mcafee_email_gateway/patches") ) exit( 0 );

if (version =~ "^7\.6\.")
{
  patch = "7.6.404h1128596";
  fix = '7.6.3334.102';
}
else
 exit( 99 );

if( patch >< patches ) exit( 99 );

if( version_is_less( version:version, test_version:fix ) )
{
  report = product + ' (' + version + ') is missing the patch ' + patch + ' (' + fix + ').\n';
  security_message( port:0, data:report );
  exit( 0 );
}


# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:vrealize_automation";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140077");
  script_cve_id("CVE-2016-5334");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("2025-09-09T14:09:45+0000");
  script_name("VMware vRealize Automation Partial Information Disclosure Vulnerability (VMSA-2016-0021)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0021.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 7.2.0 or later.");

  script_tag(name:"summary", value:"There is a partial information disclosure vulnerability in VMware Identity Manager as used by vRealize Automation.");
  script_tag(name:"insight", value:"VMware Identity Manager contains a vulnerability that may allow for a partial information disclosure. Successful exploitation of the vulnerability may allow read access to files contained in the /SAAS/WEB-INF and /SAAS/META-INF directories remotely.");

  script_tag(name:"affected", value:"vRealize Automation 7.x < 7.2.0 (vRealize Automation 7.x ships with an RPM-based version of VMware Identity Manager)");

  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-08 13:29:00 +0000 (Fri, 08 Apr 2022)");
  script_tag(name:"creation_date", value:"2016-11-23 10:02:04 +0100 (Wed, 23 Nov 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_vmware_vrealize_automation_http_detect.nasl");
  script_mandatory_keys("vmware/vrealize/automation/version");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version =~ "^7\." )
{
  if( version_is_less( version:version, test_version:"7.2.0" ) ) fix = "7.2.0";

  if( version =~ "^7\.2\.0" )
  {
    if( build = get_kb_item( "vmware/vrealize/automation/build" ) )
      if( build && int( build ) < 4660246 ) fix = "7.2.0.381 Build 4270058";
  }
}

if( fix )
{
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit(0);
}

exit( 99 );

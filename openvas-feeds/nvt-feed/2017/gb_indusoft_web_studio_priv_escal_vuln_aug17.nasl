# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:schneider_electric:indusoft_web_studio";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811264");
  script_version("2024-11-22T15:40:47+0000");
  script_cve_id("CVE-2017-7968");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:30:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-08-01 17:07:48 +0530 (Tue, 01 Aug 2017)");
  script_name("InduSoft Web Studio Privilege Escalation Vulnerability (Aug 2017) - Windows");

  script_tag(name:"summary", value:"InduSoft Web Studio is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an incorrect default
  permissions for a new directory and two files, created on installation.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  authenticated user to escalate his or her privileges and manipulate certain
  files.");

  script_tag(name:"affected", value:"Schneider Electric InduSoft Web Studio
  before 8.0 Service Pack 1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Schneider Electric InduSoft
  Web Studio 8.0 Service Pack 1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-138-02");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98544");
  script_xref(name:"URL", value:"http://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2017-090-02");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_schneider_indusoft_consolidation.nasl");
  script_mandatory_keys("schneider_indusoft/installed");
  script_xref(name:"URL", value:"http://www.indusoft.com/");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!studioVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:studioVer, test_version:"8.0.1.0"))
{
  report = report_fixed_ver( installed_version:studioVer, fixed_version:"8.0.1.0");
  security_message( data:report);
  exit(0);
}

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:creative_cloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809450");
  script_version("2024-02-27T14:36:53+0000");
  script_cve_id("CVE-2016-6935");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-27 14:36:53 +0000 (Tue, 27 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:35:00 +0000 (Mon, 28 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-10-13 15:55:28 +0530 (Thu, 13 Oct 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Creative Cloud Security Update (APSB16-34) - Windows");

  script_tag(name:"summary", value:"Adobe Creative Cloud is prone to a local privilege
  escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unquoted service
  path enumeration vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  users to gain privileges of the system thereby leading to further attcks.");

  script_tag(name:"affected", value:"Adobe Creative Cloud before version 3.8.0.310.");

  script_tag(name:"solution", value:"Update to Adobe Creative Cloud version
  3.8.0.310 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/creative-cloud/apsb16-34.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_creative_cloud_detect_win.nasl");
  script_mandatory_keys("AdobeCreativeCloud/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"3.8.0.310")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.8.0.310");
  security_message(data:report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815540");
  script_version("2024-02-21T05:06:27+0000");
  script_cve_id("CVE-2019-7968", "CVE-2019-7969", "CVE-2019-7970", "CVE-2019-7971",
                "CVE-2019-7972", "CVE-2019-7973", "CVE-2019-7974", "CVE-2019-7975",
                "CVE-2019-7976", "CVE-2019-7977", "CVE-2019-7978", "CVE-2019-7979",
                "CVE-2019-7980", "CVE-2019-7981", "CVE-2019-7982", "CVE-2019-7983",
                "CVE-2019-7984", "CVE-2019-7985", "CVE-2019-7986", "CVE-2019-7987",
                "CVE-2019-7988", "CVE-2019-7989", "CVE-2019-7990", "CVE-2019-7991",
                "CVE-2019-7992", "CVE-2019-7993", "CVE-2019-7994", "CVE-2019-7995",
                "CVE-2019-7996", "CVE-2019-7997", "CVE-2019-7998", "CVE-2019-7999",
                "CVE-2019-8000", "CVE-2019-8001");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-21 05:06:27 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-27 17:27:00 +0000 (Tue, 27 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-14 17:14:11 +0530 (Wed, 14 Aug 2019)");
  script_name("Adobe Photoshop CC Multiple Vulnerabilities (APSB19-44) - Windows");
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect.nasl");
  script_mandatory_keys("Adobe/Photoshop/Installed");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb19-44.html");

  script_tag(name:"summary", value:"Adobe Photoshop CC is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - Heap overflow errors

  - Type confusion errors

  - Out of bound read errors

  - Command injection errors

  - Out of bound write errors");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code in the context of the application and leak the memory.");

  script_tag(name:"affected", value:"- Adobe Photoshop CC 2018 19.1.8 and earlier

  - Adobe Photoshop CC 2019 20.0.5 and earlier");

  script_tag(name:"solution", value:"- Update to Adobe Photoshop CC 2018 19.1.9 or later

  - Update to Adobe Photoshop CC 2019 20.0.6 or later");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:adobe:photoshop_cc2018", "cpe:/a:adobe:photoshop_cc2019");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^19\.") {
  if(version_is_less_equal(version:vers, test_version:"19.1.8")) {
    fix = "19.1.9";
    installed_ver = "Adobe Photoshop CC 2018";
  }
}

else if(vers =~ "^20\.") {
  if(version_is_less_equal(version:vers, test_version:"20.0.5")) {
    fix = "20.0.6";
    installed_ver = "Adobe Photoshop CC 2019";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:installed_ver + " " + vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

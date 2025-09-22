# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:bridge_cc";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826463");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2021-36072", "CVE-2021-36078", "CVE-2021-36073", "CVE-2021-36079",
                "CVE-2021-36074", "CVE-2021-36075", "CVE-2021-36077", "CVE-2021-36071",
                "CVE-2021-36067", "CVE-2021-36068", "CVE-2021-36069", "CVE-2021-36049",
                "CVE-2021-36076", "CVE-2021-36059", "CVE-2021-39816", "CVE-2021-39817");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-09 13:54:00 +0000 (Thu, 09 Sep 2021)");
  script_tag(name:"creation_date", value:"2022-09-15 11:33:35 +0530 (Thu, 15 Sep 2022)");
  script_name("Adobe Bridge Multiple Vulnerabilities (APSB21-69) - Windows");

  script_tag(name:"summary", value:"Adobe Bridge is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Heap-based Buffer Overflow.

  - Multiple Access of Memory Location After End of Buffer error.

  - Multiple Buffer Overflow.

  - Multiple Out-of-bounds Read error.

  - Out-of-bounds Write error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution, arbitrary file system read, Denial of
  service and memory leak on the system.");

  script_tag(name:"affected", value:"Adobe Bridge 11.1 and earlier versions,
  10.1.2 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Update to Adobe Bridge version 11.1.1,
  10.1.3 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/bridge/apsb21-69.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_bridge_cc_detect.nasl");
  script_mandatory_keys("Adobe/Bridge/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"11.0", test_version2:"11.1"))
{
  fix = "11.1.1 or later";
}
else if(version_is_less(version:vers, test_version:"10.1.3"))
{
  fix = "10.1.3 or later";
}

if(fix)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

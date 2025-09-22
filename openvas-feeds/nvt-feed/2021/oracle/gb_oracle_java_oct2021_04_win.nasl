# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818830");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2021-35586", "CVE-2021-35564", "CVE-2021-35556", "CVE-2021-35559",
                "CVE-2021-35561", "CVE-2021-35603");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-26 13:54:00 +0000 (Tue, 26 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-25 13:13:45 +0530 (Mon, 25 Oct 2021)");
  script_name("Oracle Java SE Security Update (oct2021) 04 - Windows");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple errors in the 'ImageIO',
  'Keytool', 'Swing', 'Utility' and 'JSSE' components.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to have an
  impact on availability and confidentiality.");

  script_tag(name:"affected", value:"Oracle Java SE version 8u301 (1.8.0.301) and earlier, 7u311
  (1.7.0.311) and earlier, 11.0.12 and earlier and 17.0.0.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuoct2021.html#AppendixJAVA");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:oracle:jre";

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.301") ||
   version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.311") ||
   version_in_range(version:vers, test_version:"11.0", test_version2:"11.0.12") ||
   vers == "17.0.0") {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Apply the patch", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

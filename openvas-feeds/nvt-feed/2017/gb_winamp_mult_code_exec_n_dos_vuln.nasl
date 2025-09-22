# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nullsoft:winamp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811547");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-10725", "CVE-2017-10726", "CVE-2017-10727", "CVE-2017-10728");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-21 21:02:00 +0000 (Fri, 21 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-08-02 16:51:17 +0530 (Wed, 02 Aug 2017)");
  script_name("Winamp '.flv' File Processing Denial of Service And Code Execution Vulnerabilities");

  script_tag(name:"summary", value:"Winamp is prone to multiple denial of service and code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple memory
  corruption errors when handling malicious '.flv' files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code or cause a denial of service.");

  script_tag(name:"affected", value:"Winamp version 5.666 Build 3516(x86).");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://github.com/wlinzi/security_advisories/tree/master/CVE-2017-10725");
  script_xref(name:"URL", value:"https://github.com/wlinzi/security_advisories/tree/master/CVE-2017-10728");
  script_xref(name:"URL", value:"https://github.com/wlinzi/security_advisories/tree/master/CVE-2017-10727");
  script_xref(name:"URL", value:"https://github.com/wlinzi/security_advisories/tree/master/CVE-2017-10726");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_family("General");
  script_dependencies("secpod_winamp_detect.nasl");
  script_mandatory_keys("Winamp/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!version = get_app_version(cpe:CPE))
  exit(0);

if(version_is_equal(version:version, test_version:"5.6.6.3516")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"None");
  security_message(data:report);
  exit(0);
}

exit(0);

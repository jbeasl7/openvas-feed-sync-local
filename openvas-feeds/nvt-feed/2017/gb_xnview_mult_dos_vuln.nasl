# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xnview:xnview";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811951");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-15787", "CVE-2017-15788", "CVE-2017-15786", "CVE-2017-15785",
                "CVE-2017-15784", "CVE-2017-15783", "CVE-2017-15782", "CVE-2017-15780",
                "CVE-2017-15781", "CVE-2017-15779", "CVE-2017-15778", "CVE-2017-15777",
                "CVE-2017-15776", "CVE-2017-15775", "CVE-2017-15774", "CVE-2017-15772",
                "CVE-2017-15773", "CVE-2017-15803", "CVE-2017-15802", "CVE-2017-15801",
                "CVE-2017-15789");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-24 14:06:00 +0000 (Tue, 24 Oct 2017)");
  script_tag(name:"creation_date", value:"2017-10-25 12:35:33 +0530 (Wed, 25 Oct 2017)");

  script_name("XnView Multiple DoS Vulnerabilities");

  script_tag(name:"summary", value:"XnView is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Dll mishandling during an attempt to render the DLL icon.

  - Improper validation of '.dwg' files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code or cause a denial of service.");

  script_tag(name:"affected", value:"XnView Version 2.43");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/wlinzi/security_advisories");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_xnview_detect_win.nasl");
  script_mandatory_keys("XnView/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!xnVer = get_app_version(cpe:CPE))
  exit(0);

if(version_is_equal(version:xnVer, test_version:"2.43")) {
  report = report_fixed_ver(installed_version:xnVer, fixed_version:"WillNotFix");
  security_message(data:report);
  exit(0);
}

exit(0);

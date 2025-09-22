# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xnview:xnview";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811952");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-14580");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-21 15:32:00 +0000 (Thu, 21 Sep 2017)");
  script_tag(name:"creation_date", value:"2017-10-26 10:35:33 +0530 (Thu, 26 Oct 2017)");

  script_name("XnView 'jb2 file' DoS Vulnerability");

  script_tag(name:"summary", value:"XnView is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper handling
  of crafted '.jb2' file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code or cause a denial of service.");

  script_tag(name:"affected", value:"XnView Version 2.41");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/wlinzi/security_advisories/tree/master/CVE-2017-14580");
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

if(version_is_equal(version:xnVer, test_version:"2.41")) {
  report = report_fixed_ver(installed_version:xnVer, fixed_version:"NoneAvailable");
  security_message(data:report);
  exit(0);
}

exit(0);

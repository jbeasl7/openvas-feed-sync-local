# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:icloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811789");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2017-7127", "CVE-2017-7081", "CVE-2017-7087", "CVE-2017-7091",
                "CVE-2017-7092", "CVE-2017-7093", "CVE-2017-7094", "CVE-2017-7095",
                "CVE-2017-7096", "CVE-2017-7098", "CVE-2017-7099", "CVE-2017-7100",
                "CVE-2017-7102", "CVE-2017-7104", "CVE-2017-7107", "CVE-2017-7111",
                "CVE-2017-7117", "CVE-2017-7120", "CVE-2017-7089", "CVE-2017-7090",
                "CVE-2017-7106", "CVE-2017-7109");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-08 16:06:00 +0000 (Fri, 08 Mar 2019)");
  script_tag(name:"creation_date", value:"2017-09-26 10:42:35 +0530 (Tue, 26 Sep 2017)");
  script_name("Apple iCloud Security Updates (HT208142)");

  script_tag(name:"summary", value:"Apple iCloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple memory corruption issues.

  - A logic issue existed in the handling of parent-tab.

  - A permissions issue existed in the handling of web browser cookies.

  - An inconsistent user interface issue.

  - Application Cache policy may be unexpectedly applied.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to execute arbitrary code with system privileges,
  conduct cross site scripting, send cookies belonging to one origin to another
  origin, conduct address bar spoofing attack.");

  script_tag(name:"affected", value:"Apple iCloud versions before 7.0");

  script_tag(name:"solution", value:"Upgrade to Apple iCloud 7.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208142");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apple_icloud_detect_win.nasl");
  script_mandatory_keys("apple/icloud/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!icVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:icVer, test_version:"7.0"))
{
  report = report_fixed_ver(installed_version:icVer, fixed_version:"7.0");
  security_message(data:report);
  exit(0);
}
exit(0);

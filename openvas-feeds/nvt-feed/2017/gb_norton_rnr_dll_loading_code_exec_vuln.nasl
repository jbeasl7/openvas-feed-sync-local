# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:norton:remove_%26_reinstall";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812214");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-06 19:04:00 +0000 (Fri, 06 Oct 2017)");
  script_tag(name:"creation_date", value:"2017-11-07 14:00:28 +0530 (Tue, 07 Nov 2017)");

  script_cve_id("CVE-2017-13676");

  script_name("Norton Remove & Reinstall DLL Preloading Code Execution Vulnerability");

  script_tag(name:"summary", value:"Norton Remove & Reinstall is prone to dll preloading code
  execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to application looks to call a DLL for
  execution and an attacker provides a malicious DLL to use instead. Depending on how the
  application is configured, it will generally follow a specific search path to locate the DLL.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to do simple file
  write (or potentially an over-write) which results in a foreign DLL running under the context of
  the application.");

  script_tag(name:"affected", value:"Norton Remove & Reinstall prior to version 4.4.0.58");

  script_tag(name:"solution", value:"Update to version 4.4.0.58 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20170926_00");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100939");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_norton_remove_n_reinstall_smb_login_detect.nasl");
  script_mandatory_keys("norton/remove_n_reinstall/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

nrnVer = infos["version"];
nrnPath = infos["location"];

if(version_is_less(version:nrnVer, test_version:"4.4.0.58"))
{
  report = report_fixed_ver(installed_version:nrnVer, fixed_version:"4.4.0.58", install_path:nrnPath);
  security_message(data:report);
  exit(0);
}
exit(0);

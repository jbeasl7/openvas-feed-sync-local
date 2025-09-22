# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:norton_utilities";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814309");
  script_version("2023-07-20T05:05:18+0000");
  script_cve_id("CVE-2018-5235");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-11-02 16:40:08 +0530 (Fri, 02 Nov 2018)");
  script_name("Norton Utilities DLL Preloading Vulnerability (SYMSA1459) - Windows");

  script_tag(name:"summary", value:"Norton Utilities is prone to a local privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because when an application looks to call a DLL
  for execution, it can accept a malicious DLL also instead. The vulnerability can be exploited by a
  simple file write (or potentially an over-write) which results in a foreign DLL running under the
  context of the application.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local attacker to leverage
  this issue to execute arbitrary code in the context of the affected application. Failed exploit
  attempts will result in a denial of service condition.");

  script_tag(name:"affected", value:"Norton Utilities versions prior to 16.0.3.44.");

  script_tag(name:"solution", value:"Update to version 16.0.3.44 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.symantec.com/en_US/article.SYMSA1459.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_norton_utilities_detect_win.nasl");
  script_mandatory_keys("Norton/Utilities/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"16.0.3.44")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"16.0.3.44", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
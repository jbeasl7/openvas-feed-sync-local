# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:novell:iprint";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804308");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2013-3708");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-02-05 21:04:07 +0530 (Wed, 05 Feb 2014)");
  script_name("Novell iPrint Client Denial of Service (dos) Vulnerability - Windows");

  script_tag(name:"summary", value:"Novell iPrint Client is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to some unspecified error in 'id1.GetPrinterURLList(arg1, arg2)'
function.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct denial of
service.");
  script_tag(name:"affected", value:"Novell iPrint Client before version 5.93 on Windows.");
  script_tag(name:"solution", value:"Upgrade to version 5.93 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7014184");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("secpod_novell_prdts_detect_win.nasl");
  script_mandatory_keys("Novell/iPrint/Installed");
  script_xref(name:"URL", value:"http://www.novell.com");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!novVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:novVer, test_version:"5.93"))
{
  report = report_fixed_ver(installed_version:novVer, fixed_version:"5.93");
  security_message(port:0, data:report);
  exit(0);
}

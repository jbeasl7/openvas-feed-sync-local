# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813044");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2018-0808");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-03-16 11:09:04 +0530 (Fri, 16 Mar 2018)");
  script_name("ASP.NET Core ANCM Denial of Service Vulnerability - Windows");

  script_tag(name:"summary", value:"ASP.NET Core is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when ASP.NET Core improperly
  handles web requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause a denial of service against an ASP.NET Core web application.");

  script_tag(name:"affected", value:"Microsoft ASP.NET Core 1.0, 1.1 and 2.0 running AspNetCoreModule (ANCM) prior to 7.1.1990.0.");

  script_tag(name:"solution", value:"Upgrade to AspNetCoreModule (ANCM) version
  7.1.1990.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://github.com/aspnet/Announcements/issues/294");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103225");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0808");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Windows");
  script_dependencies("gb_asp_dotnet_core_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("ASP.NET/Core/Ver");

  exit(0);
}

include("host_details.inc");
include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

coreVers = infos["version"];
path = infos["location"];

if(coreVers != "1.0" && coreVers != "1.1" && coreVers != "2.0"){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

acnmVer = fetch_file_version(sysPath:sysPath, file_name:"inetsrv\aspnetcore.dll");
if(!acnmVer){
  exit(0);
}

if(version_is_less(version:acnmVer, test_version:"7.1.1990.0")) {
  report = report_fixed_ver(installed_version:"ASP .NET Core " + coreVers + " with ANCM " + acnmVer,
                            fixed_version:"ASP .NET Core With ANCM 7.1.1990.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

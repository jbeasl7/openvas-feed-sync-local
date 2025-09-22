# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800192");
  script_version("2025-09-04T05:39:49+0000");
  script_tag(name:"last_modification", value:"2025-09-04 05:39:49 +0000 (Thu, 04 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-01-18 07:48:41 +0100 (Tue, 18 Jan 2011)");
  script_cve_id("CVE-2010-4111");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("HP System Management Homepage (SMH) Insight Diagnostics XSS Vulnerability (HPSBMA02615) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://marc.info/?l=bugtraq&m=129245189832672&w=2");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Dec/1024897.html");
  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=emr_na-c02652463");

  script_tag(name:"summary", value:"HP System Management Homepage (SMH) with Insight Diagnostics is
  prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to inject arbitrary
  HTML code in the context of an affected site.");

  script_tag(name:"affected", value:"HP Insight Diagnostics Online Edition before 8.5.1.3712 on Windows.");

  script_tag(name:"insight", value:"The flaw is caused due imporper validation of user supplied
  input via unspecified vectors, which allows attackers to execute arbitrary HTML and script code in
  a user's browser session in the context of an affected site.");

  script_tag(name:"solution", value:"Update to version 8.5.1.3712 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key))
  exit(0);

foreach item(registry_enum_keys(key:key)) {

  hp_smh_diag_name = registry_get_sz(key:key + item, item:"DisplayName");
  if("HP Insight Diagnostics Online Edition" >!< hp_smh_diag_name)
    continue;

  hp_smh_diag_path = registry_get_sz(key:key + item, item:"InstallLocation");
  if(!hp_smh_diag_path)
    continue;

  hp_smh_diag_path = hp_smh_diag_path + "\hpdiags\hpdiags.exe";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:hp_smh_diag_path);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:hp_smh_diag_path);
  exeVer = GetVer(file:file, share:share);
  if(!exeVer)
    continue;

  if(version_is_less(version:exeVer, test_version:"8.5.1.3712")){
    report = report_fixed_ver(installed_version:exeVer, fixed_version:"8.5.1.3712");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);

# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103934");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("2025-01-17T15:39:18+0000");

  script_name("Ecava IntegraXor Account Information Disclosure Vulnerability");


  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66554");
  script_xref(name:"URL", value:"http://www.integraxor.com/");

  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2014-04-03 13:12:18 +0200 (Thu, 03 Apr 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Web Servers");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain sensitive information that
may lead to further attacks.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Updates are available.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Ecava IntegraXor is prone to an information disclosure vulnerability.");
  script_tag(name:"affected", value:"Versions prior to IntegraXor 4.1.4393 are vulnerable.");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ecavaigName = registry_get_sz(key:key + item, item:"DisplayName");

  if("IntegraXor" >< ecavaigName)
  {
    ecavaigVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(ecavaigVer != NULL)
    {
      if(version_is_less(version:ecavaigVer, test_version:"4.1.4393"))
      {
        report = report_fixed_ver(installed_version:ecavaigVer, fixed_version:"4.1.4393");
        security_message(port:0, data:report);
        exit(0);
      }
    }
  }
}


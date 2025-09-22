# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900207");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-09-02 07:39:00 +0200 (Tue, 02 Sep 2008)");
  script_cve_id("CVE-2008-3919");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_name("Ichitaro Document Handling Unspecified Code Execution Vulnerability");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://secunia.com/advisories/31603/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30828");
  script_xref(name:"URL", value:"http://www.justsystems.com/jp/info/pd8002.html");

  script_tag(name:"solution", value:"Upgrade to Justsystem Ichitaro 2010 or later.");

  script_tag(name:"summary", value:"Ichitaro is prone to an unspecified remote code execution (RCE)
  vulnerability.");

  script_tag(name:"insight", value:"The issue is due to error that exists while processing specially
  crafted document form.");

  script_tag(name:"affected", value:"Justsystem Ichitaro 2008 and prior versions on Windows (All).");

  script_tag(name:"impact", value:"Successful exploitation will allow execution arbitrary code
  within the context of the vulnerable application.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.ichitaro.com");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!registry_key_exists(key:"SOFTWARE\Justsystem\ATOK")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach entry(registry_enum_keys(key:key)) {

  appName = registry_get_sz(item:"DisplayName", key:key + entry);

  if(appName && "ATOK" >< appName) {

    if(egrep(pattern:"ATOK ([01][0-9][0-9][0-9]|200[0-8]|(9\.|1[0-3]\.)).*", string:appName)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
    exit(99);
  }
}

exit(0);
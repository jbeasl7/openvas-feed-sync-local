# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802565");
  script_version("2024-05-07T05:05:33+0000");
  script_cve_id("CVE-2012-0310", "CVE-2012-0309");
  script_tag(name:"last_modification", value:"2024-05-07 05:05:33 +0000 (Tue, 07 May 2024)");
  script_tag(name:"creation_date", value:"2012-01-20 18:01:09 +0530 (Fri, 20 Jan 2012)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Cogent OPC DataHub and Cascade DataHub < 7.2 XSS and CRLF Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN12983784/index.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51375");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN63249231/index.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2012/JVNDB-2012-000001.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2012/JVNDB-2012-000002.html");

  script_tag(name:"summary", value:"OPC DataHub or Cascade DataHub is prone to multiple cross-site
  scripting (XSS) and CRLF vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to unspecified errors in the applications,
  allows remote attackers to inject arbitrary web script or HTML via unspecified vectors.");

  script_tag(name:"solution", value:"- Update OPC DataHub to version 7.2 or later

  - Update Cascade DataHub to version 7.2 or later");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
  arbitrary HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"- OPC DataHub version 6.4.20 and prior

  - Cascade DataHub version 6.4.20 and prior");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

function version_check(ver) {
  if(version_is_less_equal(version:ver, test_version:"6.4.20")) {
    report = report_fixed_ver(installed_version:ver, vulnerable_range:"Less than or equal to 6.4.20");
    security_message(port:0, data:report);
    exit(0);
  }
}

if(registry_key_exists(key:"SOFTWARE\Cogent\OPC DataHub")) {
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OPC DataHub";
  if(registry_key_exists(key:key)) {
    dataVer = registry_get_sz(key:key, item:"DisplayVersion");
    if(dataVer){
      version_check(ver:dataVer);
    }
  }
}

if(registry_key_exists(key:"SOFTWARE\Cogent\Cascade DataHub")) {
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Cascade DataHub";
  if(!(registry_key_exists(key:key)))
    exit(0);

  dataVer = registry_get_sz(key:key, item:"DisplayVersion");
  if(!dataVer)
    exit(0);

  version_check(ver:dataVer);
}

exit(99);

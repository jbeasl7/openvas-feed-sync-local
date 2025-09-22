# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:internet2:shibboleth-sp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813051");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2018-0489");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-23 15:18:00 +0000 (Fri, 23 Mar 2018)");
  script_tag(name:"creation_date", value:"2018-03-22 14:44:12 +0530 (Thu, 22 Mar 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Shibboleth XMLTooling-C Library < 1.6.4 Security Bypass Vulnerability");

  script_tag(name:"summary", value:"Shibboleth Service Provider is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to limitations in older
  versions of the XML parser that make it impossible to fully disable Document Type
  Definition (DTD) processing. Through addition/manipulation of a DTD, it's possible
  to make changes to an XML document that do not break a digital signature but are
  mishandled by the SP and its libraries processing.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to bypass the authentication mechanism and perform unauthorized actions.
  This may lead to further attacks.");

  script_tag(name:"affected", value:"Shibboleth XMLTooling-C before 1.6.4, as used
  in Shibboleth Service Provider before 2.6.1.4.");

  script_tag(name:"solution", value:"Upgrade to Shibboleth Service Provider release
  (V2.6.1.4) or upgrade XMLTooling-C library to version 1.6.4.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://shibboleth.net/community/advisories/secadv_20180112.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103172");
  script_xref(name:"URL", value:"https://www.securitytracker.com/id/1040435");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_shibboleth_sp_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Shibboleth/SP/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

shVer = infos["version"];
location = infos["location"];

if(version_is_less(version:shVer, test_version:"2.6.1.4")) {
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
  if(path) {
    path = path + "\Shibboleth\SP\lib";

    dllVer = fetch_file_version(sysPath:path, file_name:"xmltooling1_6.dll");

    if(dllVer && version_is_less(version:dllVer, test_version:"1.6.4.0")) {
      report = report_fixed_ver(installed_version:shVer, fixed_version:"Upgrade to Shibboleth SP 2.6.1.4 or upgrade XMLTooling-C library to version 1.6.4", install_path:location);
      security_message(port:0, data:report);
      exit(0);
    }
  }
}

exit(99);

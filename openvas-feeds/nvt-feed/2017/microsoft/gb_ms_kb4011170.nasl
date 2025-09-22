# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:sharepoint_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812023");
  script_version("2025-08-05T05:45:17+0000");
  script_cve_id("CVE-2017-11775", "CVE-2017-11777");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-08-05 05:45:17 +0000 (Tue, 05 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-20 13:27:00 +0000 (Fri, 20 Oct 2017)");
  script_tag(name:"creation_date", value:"2017-10-13 10:02:45 +0530 (Fri, 13 Oct 2017)");
  script_name("Microsoft SharePoint Enterprise Server 2013 Service Pack 1 Multiple XSS Vulnerabilities (KB4011170)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4011170");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an error when
  Microsoft SharePoint Server does not properly sanitize a specially crafted
  web request to an affected SharePoint server.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to perform cross-site scripting attacks on affected systems and run
  script in the security context of the current user. The attacks could allow
  the attacker to read content that the attacker is not authorized to read, use
  the victim's identity to take actions on the SharePoint site on behalf of the
  user, such as change permissions and delete content, and inject malicious
  content in the browser of the user.");

  script_tag(name:"affected", value:"Microsoft SharePoint Enterprise Server 2013 Service Pack 1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4011170");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101105");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101155");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_sharepoint_smb_login_detect.nasl");
  script_mandatory_keys("microsoft/sharepoint/server/smb-login/detected");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(isnull(port = get_app_port(cpe:CPE, service:"smb-login")))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

shareVer = infos["version"];
if(!shareVer || shareVer !~ "^15\."){
  exit(0);
}

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Office15.OSERVER",
                         item:"InstallLocation");
if(path)
{
  path = path + "\15.0\WebServices\ConversionServices";

  dllVer = fetch_file_version(sysPath:path, file_name:"msoserver.dll");
  if(dllVer && dllVer =~ "^15\.")
  {
    if(version_is_less(version:dllVer, test_version:"15.0.4971.1000"))
    {
      report = 'File checked:     ' +  path + "\msoserver.dll"+ '\n' +
               'File version:     ' +  dllVer  + '\n' +
               'Vulnerable range: ' +  "15.0 - 15.0.4971.0999" + '\n' ;
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);

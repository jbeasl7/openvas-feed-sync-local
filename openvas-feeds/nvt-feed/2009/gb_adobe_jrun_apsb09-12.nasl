# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900823");
  script_version("2023-06-23T16:09:17+0000");
  script_tag(name:"last_modification", value:"2023-06-23 16:09:17 +0000 (Fri, 23 Jun 2023)");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-1873", "CVE-2009-1874");
  script_name("Adobe JRun 4.0 Management Console Multiple Vulnerabilities (APSB09-12)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"Adobe JRun is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"- Multiple XSS vulnerabilities exist due to error in the
  Management Console which can be exploited to inject arbitrary web script or HTML via unspecified
  vectors.

  - A Directory traversal attack is possible due to error in logging/logviewer.jsp in the Management
  Console which can be exploited by authenticated users to read arbitrary files via a .. (dot dot)
  in the logfile parameter.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause XSS
  attacks or Directory Traversal attack using the affected application.");

  script_tag(name:"affected", value:"Adobe JRun version 4.0 on Windows.");

  script_tag(name:"solution", value:"Apply the security updates from the referenced advisories.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://download.macromedia.com/pub/coldfusion/updates/jmc-app.ear");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36047");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36050");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36329/");
  script_xref(name:"URL", value:"http://www.dsecrg.com/pages/vul/show.php?id=151");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb09-12.html");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

path = registry_get_sz(key:"SOFTWARE\Macromedia\Install Data\JRun 4", item:"INSTALLDIR");
if(!path)
  exit(0);

path += "\bin\jrun.exe";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:path);
vers = GetVer(file:file, share:share);
if(!vers)
  exit(0);

if(version_in_range(version:vers, test_version:"4.0", test_version2:"4.0.7.43085")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"4.0 - 4.0.7.43085", file_checked:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

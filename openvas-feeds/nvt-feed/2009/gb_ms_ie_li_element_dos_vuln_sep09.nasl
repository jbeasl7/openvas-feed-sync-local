# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800872");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-09-02 11:50:45 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3019");
  script_name("Microsoft Internet Explorer 'li' Element DoS Vulnerability (Sep 2009)");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9455");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36070");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/36070-1.html");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/36070-3.txt");
  script_xref(name:"URL", value:"https://connect.microsoft.com/IE/feedback/ViewFeedback.aspx?FeedbackID=338599");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version", "SMB/WinXP/ServicePack");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers can cause the application
  to crash.");

  script_tag(name:"affected", value:"Microsoft, Internet Explorer version 6.x on Windows XP SP2/SP3");

  script_tag(name:"insight", value:"Error exists when application fails to handle a crafted JavaScript code, that
  calls 'createElement' to create an instance of the 'li' element, and then calls 'setAttribute' to set the value attribute.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Internet Explorer version 8 or 8 beta 2.");

  script_tag(name:"summary", value:"Internet Explorer is prone to a denial
  of service vulnerability.");

  exit(0);
}

include("smb_nt.inc");

SP = get_kb_item("SMB/WinXP/ServicePack");
if(("Service Pack 3" >< SP) || ("Service Pack 2" >< SP))
{
  ieVer = get_kb_item("MS/IE/Version");
  if(ieVer =~ "^6\..*"){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900103");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2007-2752");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Buffer overflow");
  script_name("Blue Coat K9 Web Protection Multiple Buffer Overflow Vulnerabilities");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2007-61/advisory/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30463");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30464");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2007-64/advisory/");
  script_tag(name:"summary", value:"Blue Coat K9 Web Protection is prone to a stack based buffer overflow vulnerability.");
  script_tag(name:"insight", value:"The flaws exist due to errors in filter services (k9filter.exe) when handling

  - http version information in responses from a centralised server
  (sp.cwfservice.net).

  - Referer: headers during access to the web-based K9 Web Protection
  Administration interface.");
  script_tag(name:"affected", value:"Blue Coat K9 Web Protection versions 3.2.44 and prior on Windows (All)");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause
stack based buffer overflow by sending specially crafted malicious
code containing and overly long http version information and
reference header.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("smb_nt.inc");

if (!get_kb_item("SMB/WindowsVersion")){
       exit(0);
}

blueVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\Uninstall\Blue Coat K9 Web Protection",
                          item:"DisplayVersion");

if(egrep(pattern:"^([0-2]\..*|3\.([01]\..*|2\.([0-3]?[0-9]|4[0-4])))$",
         string:blueVer)) {
       security_message( port: 0, data: "The target host was found to be vulnerable" );
}

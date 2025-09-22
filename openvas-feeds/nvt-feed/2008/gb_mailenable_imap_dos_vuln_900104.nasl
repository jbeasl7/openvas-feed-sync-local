# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900104");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2008-3449");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("MailEnable IMAP Denial of Service Vulnerability");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://www.mailenable.com/hotfix/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30498");
  script_xref(name:"URL", value:"http://www.mailenable.com/hotfix/ME-10042.EXE");
  script_xref(name:"URL", value:"http://secunia.com/advisories/31325");

  script_tag(name:"summary", value:"MailEnable Mail Server is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"insight", value:"The flaw exists due to the load created when handling multiple IMAP connections
  to the same folder.");

  script_tag(name:"affected", value:"MailEnable Enterprise Edition 3.52 and Professional Edition 3.52
  and prior on Windows (all)");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"impact", value:"Successful exploitation will potentially cause a service crash.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");

if( ! get_kb_item( "SMB/WindowsVersion" ) ) exit( 0 );

mailVer = registry_get_sz( key:"SOFTWARE\Mail Enable\Mail Enable", item:"Professional Version" );

if( ! mailVer ) {
  mailVer = registry_get_sz( key:"SOFTWARE\Mail Enable\Mail Enable", item:"Enterprise Version" );
  if( ! mailVer ) {
    exit( 0 );
  }
}

if( registry_key_exists( key:"SOFTWARE\Mail Enable\Mail Enable\Updates\ME-10042" ) ) exit( 0 );

if( egrep( pattern:"^([0-2]\..*|3\.([0-4]?[0-9]|5[0-2]))$", string:mailVer ) ) {
  security_message( port:0 );
  exit( 0 );
}

exit( 99 );
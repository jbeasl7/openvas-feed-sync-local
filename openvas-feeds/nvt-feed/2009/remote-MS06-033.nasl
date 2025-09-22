# SPDX-FileCopyrightText: 2009 Christian Eric Edjenguele
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101009");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2009-03-15 21:56:45 +0100 (Sun, 15 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2006-1300");
  script_name("Microsoft Security Bulletin MS06-033");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("find_service.nasl", "remote-detect-MSdotNET-version.nasl");
  script_mandatory_keys("dotNET/version");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2006/ms06-033");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/18920");

  script_tag(name:"solution", value:"Microsoft has released an update to correct this issue,
  please see the reference for more information.");

  script_tag(name:"summary", value:"This Information Disclosure vulnerability could allow an
  attacker to bypass ASP.Net security and gain unauthorized access to objects in the
  Application folders explicitly by name.");

  script_tag(name:"impact", value:"this could be used to produce useful information that could
  be used to try to further compromise the affected system.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");

dotnet = get_kb_item( "dotNET/version" );
if( ! dotnet ) exit( 0 );
port = get_kb_item( "dotNET/port" );

# Microsoft .NET Framework version 2.0
if( revcomp( a:dotnet, b:"2.0.50727.101") == -1 ) {
  # Report 'Microsoft ASP.NET Application Folder Information Disclosure Vulnerability (MS06-033)'
  report = 'Missing MS06-033 patch, detected Microsoft .Net Framework version: ' + dotnet;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2009 Christian Eric Edjenguele
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101006");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2009-03-15 21:21:09 +0100 (Sun, 15 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2006-3436");
  script_name("Microsoft Security Bulletin MS06-056");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("find_service.nasl", "remote-detect-MSdotNET-version.nasl");
  script_mandatory_keys("dotNET/version");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2006/ms06-056");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/20337");

  script_tag(name:"solution", value:"Microsoft has released an update to correct this issue,
  please see the reference for more information.");

  script_tag(name:"summary", value:"A cross-site scripting vulnerability exists in a server
  running a vulnerable version of the .Net Framework 2.0 that could inject a client side
  script in the user's browser.");

  script_tag(name:"impact", value:"The script could spoof content, disclose information,
  or take any action that the user could take on the affected web site.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");

dotnet = get_kb_item( "dotNET/version" );
if( ! dotnet ) exit( 0 );
port = get_kb_item( "dotNET/port" );

# Microsoft .NET Framework version 2.0
if( revcomp( a:dotnet, b:"2.0.50727.210" ) == -1 ) {
  # Report 'Microsoft .NET Framework 2.0 Cross-Site Scripting Vulnerability (MS06-056)'
  report = 'Missing MS06-056 patch, detected Microsoft .Net Framework version: ' + dotnet;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

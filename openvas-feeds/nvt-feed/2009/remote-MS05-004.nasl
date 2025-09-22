# SPDX-FileCopyrightText: 2009 Christian Eric Edjenguele
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101010");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2009-03-15 22:16:07 +0100 (Sun, 15 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 21:35:00 +0000 (Fri, 12 Oct 2018)");
  script_cve_id("CVE-2004-0847");
  script_name("Microsoft Security Bulletin MS05-004");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("find_service.nasl", "remote-detect-MSdotNET-version.nasl");
  script_mandatory_keys("dotNET/version", "dotNET/port");

  script_tag(name:"solution", value:"Microsoft has released a patch to correct this issue,
  you can download it from the references.");

  script_tag(name:"summary", value:"A canonicalization vulnerability exists in ASP.NET that could
  allow an attacker to bypass the security of an ASP.NET Web site and gain unauthorized access.");

  script_tag(name:"impact", value:"An attacker who successfully exploited this vulnerability could
  take a variety of actions, depending on the specific contents of the website.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 1.0:

  - Windows 2000 Service Pack 3 or Windows 2000 Service Pack 4

  - Windows XP Service Pack 1 or Windows XP Service Pack 2

  - Windows Server 2003, Windows Server 2003 Service Pack 1, or Windows Server 2003 Service Pack 2

  - Windows Server 2003 x64 Edition or Windows Server 2003 x64 Edition Service Pack 2

  - Windows Server 2003 for Itanium-based Systems, Windows Server 2003 with SP1 for Itanium-based Systems,
  or Windows Server 2003 with SP2 for Itanium-based Systems

  - Windows Vista

  - Windows XP Tablet PC Edition

  - Windows XP Media Center Edition

  - Windows 2000 Service Pack 3 or Windows 2000 Service Pack 4

  - Windows XP Service Pack 1 or Windows XP Service Pack 2

  - Windows Server 2003, Windows Server 2003 Service Pack 1, or Windows Server 2003 Service Pack 2

  - Windows Server 2003 x64 Edition or Windows Server 2003 x64 Edition Service Pack 2

  - Windows Server 2003 for Itanium-based Systems, Windows Server 2003 with SP1 for Itanium-based Systems,
  or Windows Server 2003 with SP2 for Itanium-based Systems

  Microsoft .NET Framework 1.1:

  - Windows 2000 Service Pack 3 or Windows 2000 Service Pack 4

  - Windows XP Service Pack 1 or Windows XP Service Pack 2

  - Windows XP Tablet PC Edition

  - Windows XP Media Center Edition

  - Windows XP Professional x64 Edition or Windows XP Professional x64 Edition Service Pack 2

  - Windows Server 2003 x64 Edition or Windows Server 2003 x64 Edition Service Pack 2

  - Windows Server 2003 for Itanium-based Systems, Windows Server 2003 with SP1 for Itanium-based Systems,
  or Windows Server 2003 with SP2 for Itanium-based Systems

  - Windows Vista

  - Windows Server 2003

  - Windows 2000 Service Pack 3 or Windows 2000 Service Pack 4

  - Windows XP Service Pack 1 or Windows XP Service Pack 2

  - Windows XP Tablet PC Edition

  - Windows XP Media Center Edition

  - Windows Server 2003 x64 Edition or Windows Server 2003 x64 Edition Service Pack 2

  - Windows Server 2003 for Itanium-based Systems, Windows Server 2003 with SP1 for Itanium-based Systems,
  or Windows Server 2003 with SP2 for Itanium-based Systems");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2005/ms05-004");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11342");

  exit(0);
}

include("revisions-lib.inc");

dotnet = get_kb_item("dotNET/version");
port = get_kb_item("dotNET/port");

if(!dotnet)
  exit(0);

dotnetversion["1.0"] = revcomp(a:dotnet, b:"1.0.3705.6021");
dotnetversion["1.1"] = revcomp(a:dotnet, b:"1.1.4322.2037");

foreach version(dotnetversion) {
  if(version == -1) {
    report = "Missing MS05-004 patch, detected Microsoft .Net Framework version: " + dotnet;
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

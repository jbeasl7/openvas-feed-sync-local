# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803555");
  script_version("2024-06-27T05:05:29+0000");
  script_cve_id("CVE-2009-1122", "CVE-2009-1535");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2013-02-28 19:00:44 +0530 (Thu, 28 Feb 2013)");
  script_name("Nmap NSE 6.01: http-iis-webdav-vuln");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Nmap NSE");

  script_xref(name:"URL", value:"http://blog.zoller.lu/2009/05/iis-6-webdac-auth-bypass-and-data.html");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2009/May/att-134/IIS_Advisory_pdf.bin");
  script_xref(name:"URL", value:"http://www.skullsecurity.org/blog/?p=271");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/787932");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securityadvisories/2009/971492");
  script_xref(name:"URL", value:"http://nmap.org/r/ms09-020");

  script_tag(name:"summary", value:"This VT has been deprecated and is therefore no longer
  functional.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

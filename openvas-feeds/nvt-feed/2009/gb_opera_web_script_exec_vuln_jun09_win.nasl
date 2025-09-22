# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900367");
  script_version("2025-03-05T05:38:52+0000");
  script_cve_id("CVE-2009-2063", "CVE-2009-2059", "CVE-2009-2070", "CVE-2009-2067");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-06-17 17:54:48 +0200 (Wed, 17 Jun 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Opera Web Script Execution Vulnerabilities (Jun 2009) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Opera browser is prone to multiple web script execution vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary web script
  and spoof an arbitrary https site by letting a browser obtain a valid certificate.");

  script_tag(name:"affected", value:"Opera version prior to 9.25 on Windows.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Error in processing a '3xx' HTTP CONNECT response before a successful SSL
  handshake, which can be exploited by modifying the CONNECT response
  to specify a 302 redirect to an arbitrary https web site.

  - Error exists while the HTTP Host header to determine the context of a
  document provided in a '4xx' or '5xx' CONNECT response from a proxy server,
  which can be exploited by modifying this CONNECT response, aka an
  'SSL tampering' attack.

  - Displays a cached certificate for a '4xx' or '5xx' CONNECT response page
  returned by a proxy server, which can be exploited by sending the browser a
  crafted 502 response page upon a subsequent request.

  - Detects http content in https web pages only when the top-level frame uses
  https. This can be exploited by modifying an http page to include an https
  iframe that references a script file on an http site, related to
  'HTTP-Intended-but-HTTPS-Loadable (HPIHSL) pages.'");

  script_tag(name:"solution", value:"Update to version 9.25 or later.");

  script_xref(name:"URL", value:"http://research.microsoft.com/apps/pubs/default.aspx?id=79323");
  script_xref(name:"URL", value:"http://research.microsoft.com/pubs/79323/pbp-final-with-update.pdf");

  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"9.25")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"9.25");
  security_message(port: 0, data: report);
}

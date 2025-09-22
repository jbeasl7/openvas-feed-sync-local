# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_xref(name:"URL", value:"http://research.microsoft.com/apps/pubs/default.aspx?id=79323");
  script_xref(name:"URL", value:"http://research.microsoft.com/pubs/79323/pbp-final-with-update.pdf");
  script_oid("1.3.6.1.4.1.25623.1.0.900369");
  script_version("2025-09-16T05:38:45+0000");
  script_cve_id("CVE-2009-2062", "CVE-2009-2058", "CVE-2009-2066", "CVE-2009-2072");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-06-17 17:54:48 +0200 (Wed, 17 Jun 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Apple Safari Web Script Execution Vulnerabilities (Jun 2009)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apple_safari_smb_login_detect.nasl");
  script_mandatory_keys("apple/safari/smb-login/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary web script
  in an https site's context and spoof an arbitrary https site by letting a
  browser obtain a valid certificate.");

  script_tag(name:"affected", value:"Safari version prior to 3.2.2 on Windows.");

  script_tag(name:"insight", value:"- Error in processes a '3xx' HTTP CONNECT response before a successful SSL
    handshake, which can be exploited by modifying the CONNECT response
    to specify a 302 redirect to an arbitrary https web site.

  - Error exists while the HTTP Host header to determine the context of a
    document provided in a '4xx' or '5xx' CONNECT response from a proxy server,
    which can be exploited by modifying this CONNECT response, aka an
    'SSL tampering' attack.

  - Error is caused when application does not require a cached certificate
    before displaying a lock icon for an https web site, while sending the
    browser a crafted '4xx' or '5xx' CONNECT response page for an https request
    sent through a proxy server.

  - Detects http content in https web pages only when the top-level frame uses
    https. This can be exploited by modifying an http page to include an https
    iframe that references a script file on an http site, related to
    'HTTP-Intended-but-HTTPS-Loadable (HPIHSL) pages.'");

  script_tag(name:"summary", value:"Safari browser is prone to web script execution vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Safari version 5.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"4.30.17.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Safari 5.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902011");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-01-04 15:26:56 +0100 (Mon, 04 Jan 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4440", "CVE-2009-4441", "CVE-2009-4442", "CVE-2009-4443");
  script_name("Sun Java System DSEE Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_sun_java_dir_server_detect_win.nasl");
  script_mandatory_keys("Sun/JavaDirServer/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to gain knowledge of potentially
  sensitive information or cause a Denial of Service.");

  script_tag(name:"affected", value:"Sun Java System DSEE version 6.0 through 6.3.1 on Windows.");

  script_tag(name:"insight", value:"- An error in Directory Proxy Server may cause a client operation to
    temporarily run with another client's privileges.

  - An error in Directory Proxy Server can be exploited via specially crafted
    packets to cause the service to stop responding to new client connections.

  - An error in Directory Proxy Server can be exploited via a specially crafted
   'psearch' client to exhaust available CPU resources, preventing the server
    from sending results to other 'psearch' clients.");

  script_tag(name:"summary", value:"Sun Java System Directory Server Enterprise Edition (DSEE) is prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Apply patch 141958-01 or later for Sun Java System DSEE version 6.3.1.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37915/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37481");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3647");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-270789-1");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-21-141958-01-1");

  exit(0);
}

include("version_func.inc");

ver = get_kb_item("Sun/JavaDirServer/Win/Ver");
if( ! ver || ver !~ "^6\." ) exit( 0 );

if(version_in_range(version:ver, test_version:"6.0", test_version2:"6.3.1")) {
  security_message(port:0);
  exit(0);
}
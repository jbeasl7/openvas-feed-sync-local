# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900443");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-01-29 15:16:47 +0100 (Thu, 29 Jan 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-0179");
  script_name("MikMod Module Player Denial of Service Vulnerability - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33485");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33235");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=461519");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=476339");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_mikmod_detect.nasl");
  script_mandatory_keys("MikMod/Linux/Ver");

  script_tag(name:"affected", value:"MikMod Module Player version 3.1.11 to 3.2.0 on Linux.");

  script_tag(name:"insight", value:"The following issues exist:

  - libmikmod library using a global variable to keep track of the number of
    channels can be exploited to crash an application using the library by
    loading a module with more channels than the currently playing module.

  - Error when processing the header of certain XM files which can be
    exploited to crash an application using the library via a specially
    crafted XM file.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"MikMod Module Player is prone to a Denial of Service vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker crash the application to cause
  denial-of-service condition.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

mikmodVer = get_kb_item("MikMod/Linux/Ver");
if(mikmodVer != NULL)
{
  if(version_in_range(version:mikmodVer, test_version:"3.1.11", test_version2:"3.2.0")) {
    report = report_fixed_ver(installed_version:mikmodVer, vulnerable_range:"3.1.11 - 3.2.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

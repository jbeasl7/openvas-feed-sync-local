# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900424");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-12-31 15:14:17 +0100 (Wed, 31 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5397", "CVE-2008-5398");
  script_name("TOR Privilege Escalation Vulnerability - Linux");
  script_xref(name:"URL", value:"http://www.torproject.org");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32648");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33025");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("secpod_tor_detect_lin.nasl");
  script_mandatory_keys("Tor/Linux/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker gain privileges and escalate
  the privileges in malicious ways.");

  script_tag(name:"affected", value:"Tor version 0.2.0.31 or prior.");

  script_tag(name:"insight", value:"The flaws are due to:

  - an application does not properly drop privileges to the primary groups
  of the user specified by the User Parameter.

  - a ClientDNSRejectInternalAddresses configuration option is not always
  enforced which weaknesses the application security.");

  script_tag(name:"solution", value:"Upgrade to the latest version 0.2.0.32.");

  script_tag(name:"summary", value:"TOR is prone to a privilege escalation vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ver = get_kb_item("Tor/Linux/Ver");
if(ver)
{
  if(version_is_less_equal(version:ver, test_version:"0.2.0.31")){
    report = report_fixed_ver(installed_version:ver, vulnerable_range:"Less than or equal to 0.2.0.31");
    security_message(port: 0, data: report);
  }
}

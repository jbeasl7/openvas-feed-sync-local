# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900323");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-0654");
  script_name("Tor <= 0.2.0.34 Replay Attack Vulnerability - Linux");
  script_xref(name:"URL", value:"http://blog.torproject.org/blog/one-cell-enough");
  script_xref(name:"URL", value:"http://www.blackhat.com/presentations/bh-dc-09/Fu/BlackHat-DC-09-Fu-Break-Tors-Anonymity.pdf");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_tor_detect_lin.nasl");
  script_mandatory_keys("Tor/Linux/Ver");

  script_tag(name:"affected", value:"Tor version 0.2.0.34 and prior on Linux.");

  script_tag(name:"insight", value:"Flaw is in the data flow at the end of the circuit which lets the attacker
  to modify the relayed data.");

  script_tag(name:"solution", value:"Upgrade to Tor version 0.2.1.25 or later.");

  script_tag(name:"summary", value:"Tor Anonymity Proxy is prone to replay attack vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attacker cause replay attacks
  in the network and can compromise router functionalities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

torVer = get_kb_item("Tor/Linux/Ver");
if(!torVer)
  exit(0);

if(version_is_less_equal(version:torVer, test_version:"0.2.0.34")){
  report = report_fixed_ver(installed_version:torVer, vulnerable_range:"Less than or equal to 0.2.0.34");
  security_message(port: 0, data: report);
}

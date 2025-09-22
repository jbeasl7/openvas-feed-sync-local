# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901100");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-01-28 16:24:05 +0100 (Thu, 28 Jan 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-0383", "CVE-2010-0385");
  script_name("Tor < 0.2.1.22, 0.2.2.x < 0.2.2.7-alpha Directory Queries Information Disclosure Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38198");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37901");
  script_xref(name:"URL", value:"http://archives.seul.org/or/talk/Jan-2010/msg00162.html");
  script_xref(name:"URL", value:"http://archives.seul.org/or/announce/Jan-2010/msg00000.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tor_detect_win.nasl");
  script_mandatory_keys("Tor/Win/Ver");

  script_tag(name:"affected", value:"Tor version prior to 0.2.1.22 and 0.2.2.x before 0.2.2.7-alpha on Windows.");

  script_tag(name:"insight", value:"The issue is due to bridge directory authorities disclosing all tracked
  bridge identities when responding to 'dbg-stability.txt' directory queries.");

  script_tag(name:"solution", value:"Upgrade to version 0.2.1.22 or later.");

  script_tag(name:"summary", value:"Tor is prone to an information disclosure vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain sensitive information
  that can help them launch further attacks.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

if(!version = get_kb_item("Tor/Win/Ver"))
  exit(0);

version = ereg_replace(pattern:"-", replace:".", string:version);

if(version_is_less(version:version, test_version:"0.2.1.22")) {
  security_message(port:0);
  exit(0);
}

if(version =~ "^0\.2\.2\." && version_is_less(version:version, test_version:"0.2.2.7.alpha")) {
  security_message(port:0);
  exit(0);
}

exit(99);

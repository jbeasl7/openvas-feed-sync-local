# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800410");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-06 13:48:17 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-0177");
  script_name("VMware Products vmware-authd DoS Vulnerability (CVE-2009-0177) - Windows");
  script_xref(name:"URL", value:"http://milw0rm.com/exploits/7647");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33095");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33372");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/0024");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Jan/1021512.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");

  script_tag(name:"affected", value:"VMware Player version 2.5.1 or prior on Windows.
  VMware Workstation version 6.5.1 or prior on Windows.");

  script_tag(name:"insight", value:"VMware product(s) throws an error in the vmware-authd daemon when processing
  overly long strings. This will terminate the vmware-authd process via an
  overly long 'USER' or 'PASS' strings sent to TCP port 912.");

  script_tag(name:"summary", value:"VMWare product(s) are prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker deny virtual machines
  access to local users.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");

if(!get_kb_item("VMware/Win/Installed")){
  exit(0);
}

vmplayerVer = get_kb_item("VMware/Player/Win/Ver");
if(vmplayerVer)
{
  if(version_is_less_equal(version:vmplayerVer, test_version:"2.5.1"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vmworkstnVer = get_kb_item("VMware/Workstation/Win/Ver");
if(vmworkstnVer)
{
  if(version_is_less_equal(version:vmworkstnVer, test_version:"6.5.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

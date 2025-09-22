# SPDX-FileCopyrightText: 2008 Ferdy Riphagen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.25550");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2006-2679");
  script_xref(name:"OSVDB", value:"25888");
  script_name("Cisco VPN Client Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Windows");
  script_copyright("Copyright (C) 2008 Ferdy Riphagen");
  script_dependencies("cisco_vpn_client_detect.nasl");
  script_mandatory_keys("SMB/CiscoVPNClient/Version");

  script_tag(name:"solution", value:"Upgrade to version 4.8.01.0300 or a later.");

  script_tag(name:"summary", value:"The installed Cisco VPN Client version is prone to a privilege
  escalation attack.");

  script_tag(name:"insight", value:"By using the 'Start before logon' feature in the
  VPN client dialer, a local attacker may gain privileges and execute
  arbitrary commands with SYSTEM privileges.");

  script_xref(name:"URL", value:"http://www.cisco.com/warp/public/707/cisco-sa-20060524-vpnclient.shtml");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/18094");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

version = get_kb_item("SMB/CiscoVPNClient/Version");
if (version) {
  # These versions are reported vulnerable:
  # - 2.x, 3.x, 4.0.x, 4.6.x, 4.7.x, 4.8.00.x
  # Not vulnerable:
  # - 4.7.00.0533
  if ("4.7.00.0533" >< version)
    exit(0);

  if (egrep(pattern:"^([23]\.|4\.([067]\.|8\.00)).+", string:version)) {
    report = report_fixed_ver(installed_version:version, fixed_version:"4.8.01.0300");
    security_message(port:0, data:report);
  }
}

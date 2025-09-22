# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900407");
  script_version("2025-06-24T05:41:22+0000");
  script_tag(name:"last_modification", value:"2025-06-24 05:41:22 +0000 (Tue, 24 Jun 2025)");
  script_tag(name:"creation_date", value:"2008-12-10 17:58:14 +0100 (Wed, 10 Dec 2008)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5256");
  script_name("Sun xVM VirtualBox < 2.0.6 Insecure Temporary Files Vulnerability - Windows");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://secunia.com/Advisories/32851");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32444");

  script_tag(name:"summary", value:"Sun xVM VirtualBox is prone to an 'insecure temporary files'
  vulnerability.");

  script_tag(name:"insight", value:"Error is due to insecured handling of temporary files in the
  'AcquireDaemonLock' function in ipcdUnix.cpp. This allows local users to overwrite arbitrary files
  via a symlink attack on a '/tmp/.vbox-$USER-ipc/lock' temporary file.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker perform malicious
  actions with the escalated privileges.");

  script_tag(name:"affected", value:"Sun xVM VirtualBox versions prior to 2.0.6.");

  script_tag(name:"solution", value:"Update to version 2.0.6 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

xvm_key = registry_get_sz(key:"SOFTWARE\Sun\xVM VirtualBox", item:"Version");
if(xvm_key) {
  pattern = "^([01](\..*)?|2\.0(\.[0-5])?)$";
  if(egrep(pattern:pattern, string:xvm_key)) {
    report = report_fixed_ver(installed_version:xvm_key, fixed_version:"2.0.6");
    security_message(port:0, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);

# SPDX-FileCopyrightText: 2010 LSS
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102018");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2010-04-02 10:10:27 +0200 (Fri, 02 Apr 2010)");
  script_cve_id("CVE-2007-5003");
  script_name("CA ARCserve Backup Multiple Buffer Overflow Vulnerabilities");
  script_xref(name:"URL", value:"https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID=156002");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/24348");
  script_xref(name:"URL", value:"http://research.eeye.com/html/advisories/published/AD20070920.html");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Buffer overflow");
  script_dependencies("arcserve_backup_detect.nasl");
  script_require_ports(1900);
  script_mandatory_keys("arcserve/installed");

  script_tag(name:"solution", value:"The vendor released an advisory and updates to address these issues.
  Please see the references for more information.");

  script_tag(name:"summary", value:"Multiple stack-based buffer overflows in CA (Computer Associates)
  BrightStor ARCserve Backup for Laptops and Desktops r11.0 through r11.5 allow remote attackers to
  execute arbitrary code via a long (1) username or (2) password to the rxrLogin command in rxRPC.dll,
  or a long (3) username argument to the GetUserInfo function.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

arcserve_port = 1900;
if(!get_port_state(arcserve_port)) exit(0);

ver = get_kb_item(string("arcserve/", arcserve_port, "/version"));

if (!ver) exit(0);

if(eregmatch(pattern:"11\.[0-5]+\.[0-9]+",string:ver)) {
  security_message(port:arcserve_port);
  exit(0);
}

exit(99);
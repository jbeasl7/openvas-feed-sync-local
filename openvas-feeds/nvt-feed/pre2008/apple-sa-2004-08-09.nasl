# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14251");
  script_version("2024-02-09T14:47:30+0000");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"OSVDB", value:"7098");
  script_cve_id("CVE-2003-1011");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Apple SA 2003-12-19");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_pkgs", "ssh/login/uname", re:"ssh/login/uname=Darwin.* (6\.8\.|7\.2\.)");

  script_xref(name:"URL", value:"http://docs.info.apple.com/article.html?artnum=61798");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/8945");

  script_tag(name:"solution", value:"Install Security Update 2003-12-19 or later.");

  script_tag(name:"summary", value:"The remote host is missing Security Update 2003-12-19.");

  script_tag(name:"impact", value:"Mac OS X contains a flaw that may allow a malicious user
  with physical access to gain root access.

  It is possible that the flaw may allow root access resulting
  in a loss of integrity.");

  script_tag(name:"insight", value:"The issue is triggered when the Ctrl and c keys are pressed
  on the connected USB keyboard during boot and thus interrupting the system initialization.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

packages = get_kb_item("ssh/login/osx_pkgs");
if ( ! packages ) exit(0);

uname = get_kb_item("ssh/login/uname");
# Mac OS X 10.2.8 and 10.3.2 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.2\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd2003-12-19", string:packages) )
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

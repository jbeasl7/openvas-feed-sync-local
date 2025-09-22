# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100815");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-09-20 15:31:27 +0200 (Mon, 20 Sep 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Stuxnet Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://vil.nai.com/vil/Content/v_268468.htm");
  script_xref(name:"URL", value:"http://www.stuxnet.net/");

  script_tag(name:"summary", value:"The remote Host seems to be infected by the Stuxnet worm.

  The Scanner found files on the remote host that indicate that this host is
  infected by the Stuxnet worm.");

  script_tag(name:"solution", value:"Remove all Stuxnet related files found.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

rootfile = smb_get_systemroot();
if ( ! rootfile ) exit(0);

# http://vil.nai.com/vil/Content/v_268468.htm
# Filenames are hardcoded...
stux = make_list('system32\\s7otbxsx.dll',
                 'inf\\mdmcpq3.PNF',
                 'inf\\mdmeric3.PNF',
                 'inf\\oem6C.PNF',
                 'inf\\oem7A.PNF',
                 'system32\\drivers\\mrxcls.sys',
                 'system32\\drivers\\mrxnet.sys');


report = string("The following Stuxnet related files are detected on the remote Host:\n\n");

foreach file (stux) {

   my_file = string(rootfile, "\", file);
   myread = smb_read_file(fullpath:my_file, offset:0, count:8);
   if(myread) {
     stux_found = TRUE;
     report += my_file + '\n';
   }
}

if(stux_found) {
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
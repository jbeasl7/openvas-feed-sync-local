# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107481");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-01-26 09:49:54 +0100 (Sat, 26 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Siemens SIMATIC WinCC/Audit Viewer Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");

  script_tag(name:"summary", value:"Detects the installed version
  of Siemens SIMATIC WinCC/Audit Viewer for Windows

  This VT is a duplicate of the existing VT 'Siemens SIMATIC WinCC/Audit Viewer Version Detection (Windows)' (OID: 1.3.6.1.4.1.25623.1.0.107574).");

  script_xref(name:"URL", value:"https://w3.siemens.com/mcms/human-machine-interface/de/visualisierungssoftware/scada-wincc/wincc-optionen/wincc-audit/Seiten/Default.aspx");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

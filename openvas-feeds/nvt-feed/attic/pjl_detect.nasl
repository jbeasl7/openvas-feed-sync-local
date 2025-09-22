# SPDX-FileCopyrightText: 2008 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80079");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Printer Job Language (PJL) Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2008 Michel Arboi");

  script_xref(name:"URL", value:"http://www.maths.usyd.edu.au/u/psz/ps.html");
  script_xref(name:"URL", value:"http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=bpl04568");
  script_xref(name:"URL", value:"http://h20000.www2.hp.com/bc/docs/support/SupportManual/bpl13208/bpl13208.pdf");
  script_xref(name:"URL", value:"http://h20000.www2.hp.com/bc/docs/support/SupportManual/bpl13207/bpl13207.pdf");

  script_tag(name:"summary", value:"The remote service uses the PJL (Printer Job Language) protocol and
  answered to a HP PJL request.

  This is indicates the remote device is probably a printer running JetDirect.

  Through PJL, users can submit printing jobs, transfer files to or from the printers, change some settings, etc...

  This VT has been deprecated and replaced by the VT 'Printer Job Language (PJL) / Printer Command Language (PCL) Detection'
  (OID: 1.3.6.1.4.1.25623.1.0.108641).");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

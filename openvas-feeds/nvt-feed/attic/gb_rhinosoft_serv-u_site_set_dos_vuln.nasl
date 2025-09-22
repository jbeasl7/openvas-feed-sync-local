# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801118");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3655");

  script_name("Rhino Software Serv-U 'SITE SET' Command DoS Vlnerability");

  script_xref(name:"URL", value:"http://www.serv-u.com/releasenotes/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36873/");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");

  script_tag(name:"impact", value:"Successful exploitation will let the local attackers to cause a Denial of
  Service in the affected application.");

  script_tag(name:"affected", value:"Rhino Software Serv-U version prior to 9.0.0.1.");

  script_tag(name:"insight", value:"An error occurs when application handles the 'SITE SET TRANSFERPROGRESS ON'
  command.");

  script_tag(name:"solution", value:"Update to Rhino Software Serv-U version 9.0.0.1 or later.");

  script_tag(name:"summary", value:"Rhino Software Serv-U is prone to a denial of service (DoS) vulnerability.

  This VT has been deprecated and replaced by the VT 'Serv-U 'SITE SET TRANSFERPROGRESS ON' Command Remote Denial of Service Vulnerability' (OID: 1.3.6.1.4.1.25623.1.0.100338).");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

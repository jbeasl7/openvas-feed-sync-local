# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52362");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0607");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: racoon");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");

  script_tag(name:"insight", value:"The following package is affected: racoon

The installed version of racoon does not properly
check the validity of certificates, ignoring validation
failures from OpenSSL.  This can be used by attackers to
bypass authentication restrictions.

This VT has been deprecated as a duplicate of the VT 'FreeBSD Ports: racoon' (OID: 1.3.6.1.4.1.25623.1.0.57147).");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.kame.net/racoon/racoon-ml/msg00517.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10546");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=108726102304507");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/2328adef-157c-11d9-8402-000d93664d5c.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

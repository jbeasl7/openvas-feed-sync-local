# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112333");
  script_version("2025-02-20T08:47:14+0000");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-07-25 09:39:41 +0200 (Wed, 25 Jul 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:18:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2016-5649");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Netgear DGN2200 / DGND3700 Admin Password Disclosure - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"A vulnerability exists in the 'BSW_cxttongr.htm' page which can
  allow a remote attacker to access this page without any authentication.

  This VT has been deprecated as a duplicate of the VT 'Netgear DGN2200 / DGND3700 Password
  Disclosure Vulnerability - Active Check' (OID: 1.3.6.1.4.1.25623.1.0.106497).");

  script_tag(name:"vuldetect", value:"Sends a request to the vulnerable page and tries to obtain the
  admin password.");

  script_tag(name:"insight", value:"When the request is processed, it exposes the admin's password
  in clear text before it gets redirected to absw_vfysucc.cgia.");

  script_tag(name:"impact", value:"An attacker can use this password to gain administrator access of
  the targeted routers web interface.");

  script_tag(name:"affected", value:"Netgear DGN2200 running firmware version
  DGN2200-V1.0.0.50_7.0.50.

  Netgear DGND3700 running firmware version DGND3700-V1.0.0.17_1.0.17.");

  script_tag(name:"solution", value:"Netgear has released firmware version 1.0.0.52 for DGN2200 and
  1.0.0.28 for DGND3700 to address this issue.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/140342/Netgear-DGN2200-DGND3700-WNDR4500-Information-Disclosure.html");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);


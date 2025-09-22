# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814040");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2018-09-21 12:06:57 +0530 (Fri, 21 Sep 2018)");
  script_name("Adobe Flash Player End of Life (EOL) Detection - Mac OS X");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");

  script_tag(name:"summary", value:"The Adobe Flash Player on the remote host has reached the end of
  life (EOL) / is discontinued and should not be used anymore.

  This VT has been deprecated and replaced by the VT 'Adobe Flash Player End of Life (EOL) Detection' (OID:
  1.3.6.1.4.1.25623.1.0.117197).");

  script_tag(name:"vuldetect", value:"Checks if the target host is using an EOL / discontinued
  product.");

  script_tag(name:"impact", value:"An EOL / discontinued product is not receiving any security
  updates from the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to
  compromise the security of this host.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: The product has reached its EOL.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105383");
  script_version("2025-03-25T05:38:57+0000");
  script_tag(name:"last_modification", value:"2025-03-25 05:38:57 +0000 (Tue, 25 Mar 2025)");
  script_tag(name:"creation_date", value:"2015-09-23 10:26:45 +0200 (Wed, 23 Sep 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("AMI MegaRAC SP Firmware Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");

  script_tag(name:"summary", value:"HTTP based detection of AMI MegaRAC SP Firmware.

  This VT has been deprecated and replaced by the VT 'AMI MegaRAC SP / SP-X Detection (HTTP)' (OID:
  1.3.6.1.4.1.25623.1.0.150788).");

  script_xref(name:"URL", value:"https://www.ami.com/megarac/");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

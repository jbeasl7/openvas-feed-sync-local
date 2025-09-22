# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126500");
  script_version("2023-09-07T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-09-07 05:05:21 +0000 (Thu, 07 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-08-18 07:32:07 +0000 (Fri, 18 Aug 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WildFly Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");

  script_tag(name:"summary", value:"HTTP based detection of WildFly.

  This VT has been deprecated as a duplicate of the VT 'Red Hat/JBoss WildFly Detection (HTTP)'
  (OID: 1.3.6.1.4.1.25623.1.0.111036).");

  script_xref(name:"URL", value:"https://www.wildfly.org/");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

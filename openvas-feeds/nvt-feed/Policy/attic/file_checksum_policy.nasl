# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96214");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2012-10-25 11:26:06 +0200 (Thu, 25 Oct 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Check for File Checksum Violations");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Policy");

  script_tag(name:"summary", value:"Check for File Checksum Violations

  ATTENTION: This VT is deprecated. Please use the new set of 4 VTs to handle
  file checksum policies which are to be found in the family 'Policy'.");

  script_tag(name:"deprecated", value:TRUE);

  script_tag(name:"qod_type", value:"general_note");

  exit(0);
}

exit(66);

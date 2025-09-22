# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.890857");
  script_version("2024-06-13T05:05:46+0000");
  script_name("Debian LTS: Security Advisory for libdatetime-timezone-perl (DLA-857-1)");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2018-01-15 00:00:00 +0100 (Mon, 15 Jan 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/03/msg00014.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_tag(name:"affected", value:"libdatetime-timezone-perl on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
1:1.58-1+2017a.

We recommend that you upgrade your libdatetime-timezone-perl packages.");

  script_tag(name:"summary", value:"This update includes the changes in tzdata 2017a for the
Perl bindings. For the list of changes, see DLA-856-1.

  This VT has been deprecated as it doesn't have any security relevance.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

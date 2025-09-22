# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.890895");
  script_version("2024-06-13T05:05:46+0000");
  script_name("Debian LTS: Security Advisory for openoffice.org-dictionaries (DLA-895-1)");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2018-01-17 00:00:00 +0100 (Wed, 17 Jan 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/04/msg00014.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_tag(name:"affected", value:"openoffice.org-dictionaries on Debian Linux");

  script_tag(name:"solution", value:"For Debian 7 'Wheezy', this problem has been fixed in version
3.3.0~rc10-4+deb7u1.

We recommend that you upgrade your openoffice.org-dictionaries packages.");

  script_tag(name:"summary", value:"The dictionaries provided by this package had an unversioned conflict
against the thunderbird package (which so far was not part of wheezy).

Since the next update of Icedove introduces a thunderbird package the
dictionaries would become unusable in Icedove so the (unneeded) conflict
was dropped.

  This VT has been deprecated as it doesn't have any security relevance.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2017.04");
  script_cve_id("CVE-2017-5397");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-02 22:03:00 +0000 (Wed, 02 Oct 2019)");

  script_name("Mozilla Firefox Security Advisory (MFSA2017-04) - Deprecated");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");

  script_xref(name:"Advisory-ID", value:"MFSA2017-04");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-04/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1337304");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.

  This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2017-5397: Firefox for Android cache directory is world writable
The cache directory on the local file system is set to be world writable. Firefox defaults to extracting libraries from this cache. This allows for the possibility of an installed malicious application or tools with write access to the file system to replace files used by Firefox with their own versions.");

  script_tag(name:"affected", value:"Firefox version(s) below 51.0.3.");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the reference(s) for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

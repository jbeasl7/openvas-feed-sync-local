# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2014.33");
  script_cve_id("CVE-2014-1515");
  script_tag(name:"creation_date", value:"2021-11-11 09:42:47 +0000 (Thu, 11 Nov 2021)");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Mozilla Firefox Security Advisory (MFSA2014-33) - Deprecated");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");

  script_xref(name:"Advisory-ID", value:"MFSA2014-33");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-33/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=945429");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.

  This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"File: protocol links downloaded to SD card by default
Security researcher Roee Hay reported that a hyperlink using
the file: protocol on Firefox for Android could link to a local
file in the Firefox profile directory. If a user selected this link on their
device, the linked file would be copied to the SD card without prompting.
This SD card location is world readable leading to a potential information
disclosure of files in the Firefox profile through a malicious application.");

  script_tag(name:"affected", value:"Firefox version(s) below 28.0.1.");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the reference(s) for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

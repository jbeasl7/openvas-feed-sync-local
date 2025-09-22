# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70732");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-3953", "CVE-2011-3954", "CVE-2011-3955", "CVE-2011-3956", "CVE-2011-3957", "CVE-2011-3958", "CVE-2011-3959", "CVE-2011-3960", "CVE-2011-3961", "CVE-2011-3962", "CVE-2011-3963", "CVE-2011-3964", "CVE-2011-3965", "CVE-2011-3966", "CVE-2011-3967", "CVE-2011-3968", "CVE-2011-3969", "CVE-2011-3970", "CVE-2011-3971", "CVE-2011-3972");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-02-12 07:27:19 -0500 (Sun, 12 Feb 2012)");
  script_name("FreeBSD Ports: chromium");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");

  script_tag(name:"insight", value:"The following package is affected: chromium

CVE-2011-3953
Google Chrome before 17.0.963.46 does not prevent monitoring of the
clipboard after a paste event, which has unspecified impact and remote
attack vectors.

CVE-2011-3954
Google Chrome before 17.0.963.46 allows remote attackers to cause a
denial of service (application crash) via vectors that trigger a large
amount of database usage.

CVE-2011-3955
Google Chrome before 17.0.963.46 allows remote attackers to cause a
denial of service (application crash) or possibly have unspecified
other impact via vectors that trigger the aborting of an IndexedDB
transaction.

CVE-2011-3956
The extension implementation in Google Chrome before 17.0.963.46 does
not properly handle sandboxed origins, which might allow remote
attackers to bypass the Same Origin Policy via a crafted extension.

CVE-2011-3957
Use-after-free vulnerability in the garbage-collection functionality
in Google Chrome before 17.0.963.46 allows remote attackers to cause a
denial of service or possibly have unspecified other impact via
vectors involving PDF documents.

CVE-2011-3958
Google Chrome before 17.0.963.46 does not properly perform casts of
variables during handling of a column span, which allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via a crafted document.

Text truncated. Please see the references for more information.

This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/search/label/Stable%20updates");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/fe1976c2-5317-11e1-9e99-00262d5ed8ee.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
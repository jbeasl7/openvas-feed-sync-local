# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61921");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-11-24 23:46:43 +0100 (Mon, 24 Nov 2008)");
  script_cve_id("CVE-2008-5162");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-14 16:09:58 +0000 (Wed, 14 Feb 2024)");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-08:11.arc4random.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"arc4random(9) is a generic-purpose random number generator based on the
key stream generator of the RC4 cipher.  It is expected to be
cryptographically strong, and used throughout the FreeBSD kernel for a
variety of purposes, some of which rely on its cryptographic strength.
arc4random(9) is periodically reseeded with entropy from the FreeBSD
kernel's Yarrow random number generator, which gathers entropy from a
variety of sources including hardware interrupts.  During the boot
process, additional entropy is provided to the Yarrow random number
generator from userland, helping to ensure that adequate entropy is
present for cryptographic purposes.

When the arc4random(9) random number generator is initialized, there may
be inadequate entropy to meet the needs of kernel systems which rely on
arc4random(9), and it may take up to 5 minutes before arc4random(9) is
reseeded with secure entropy from the Yarrow random number generator.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-08:11.arc4random.asc");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-08:11.arc4random.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"7.0", patchlevel:"6")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"6.3", patchlevel:"6")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}
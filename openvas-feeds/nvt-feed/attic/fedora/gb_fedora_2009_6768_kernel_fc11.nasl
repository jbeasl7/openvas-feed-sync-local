# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64291");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-06-30 00:29:55 +0200 (Tue, 30 Jun 2009)");
  script_cve_id("CVE-2009-1385", "CVE-2009-1389");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Fedora Core 11 FEDORA-2009-6768 (kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Update to kernel 2.6.29.5

Includes DRM modesetting bug fixes.

Adds driver for VIA SD/MMC controllers and full
support for the Nano processor in 64-bit mode.

ChangeLog:

  * Tue Jun 16 2009 Chuck Ebbert  2.6.29.5-191

  - Copy latest version of the -mm streaming IO and executable pages patches from F-10

  - Copy the saner-vm-settings patch from F-10:
change writeback interval from 5, 30 seconds to 3, 10 seconds

  - Comment out the null credentials debugging patch (bug #494067)

  * Tue Jun 16 2009 Chuck Ebbert  2.6.29.5-190

  - Two r8169 driver updates from 2.6.30

  - Update via-sdmmc driver

  * Tue Jun 16 2009 Chuck Ebbert  2.6.29.5-189

  - New debug patch for bug #494067, now enabled for non-debug kernels too.

  * Tue Jun 16 2009 Chuck Ebbert  2.6.29.5-188

  - Avoid lockup on OOM with /dev/zero

  * Tue Jun 16 2009 Chuck Ebbert  2.6.29.5-187

  - Drop the disable of mwait on VIA Nano processor. The lockup bug is
fixed by BIOS updates.

  * Tue Jun 16 2009 Ben Skeggs  2.6.29.5-186

  - nouveau: Use VBIOS image from PRAMIN in preference to PROM (#492658)

  * Tue Jun 16 2009 Dave Airlie  2.6.29.5-185

  - drm-connector-dpms-fix.patch - allow hw to dpms off

  - drm-dont-frob-i2c.patch - don't play with i2c bits just do EDID

  - drm-intel-tv-fix.patch - fixed intel tv after connector dpms

  - drm-modesetting-radeon-fixes.patch - fix AGP issues (go faster) (otaylor)

  - drm-radeon-fix-ring-commit.patch - fix stability on some radeons

  - drm-radeon-new-pciids.patch - add rv770/790 support

  - drm-intel-vmalloc.patch - fix vmalloc patch");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update kernel' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-6768");
  script_tag(name:"summary", value:"The remote host is missing an update to kernel
announced via advisory FEDORA-2009-6768.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=502981");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=504726");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

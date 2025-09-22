# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.1094.1");
  script_cve_id("CVE-2025-22869", "CVE-2025-22870");
  script_tag(name:"creation_date", value:"2025-04-04 04:06:21 +0000 (Fri, 04 Apr 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:1094-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1094-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251094-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239322");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-April/038880.html");
  script_xref(name:"URL", value:"https://warewulf.org/docs/v4.6.x/release/v4.6.0.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'warewulf4' package(s) announced via the SUSE-SU-2025:1094-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for warewulf4 fixes the following issues:

warewulf4 was updated from version 4.5.8 to 4.6.0:

- Security issues fixed for version 4.6.0:

 * CVE-2025-22869: Fixed Denial of Service vulnerability in the Key Exchange of golang.org/x/crypto/ssh (bsc#1239322)
 * CVE-2025-22870: Fixed proxy bypass using IPv6 zone IDs (bsc#1238611)

- User visible changes:

 * Default values `nodes.conf`:

 + The default values for `kernel command line`, `init parameters` and `root` are now set in the `default` profile
 and this profileshould be included in every profile.
 During the installation of an update an upgrade is done to `nodes.conf` which updates the database accordingly.

 * Overlay split up:

 + The overlays `wwinit` and `runtime` are now split up in different overlays named according to their role.
 The upgrade process will update the node database and replace the overlays `wwinit` and `runtime` with a list
 of overlays with same role.

 * Site and distribution overlays:

 + The overlays in `/var/lib/warewulf/overlays` should not be changed by the user any more.
 Site specific overlays are now sorted under `/etc/warewulf/overlays`.
 On upgrade, changed overlays are stored with the `rpmsave` suffix and move to
 `/etc/warewulf/overlays/$OVERLAYNAME`.

- Other changes and bugs fixed:

 * Fixed udev issue with assigning device names (bsc#1226654)
 * Implemented new package `warewulf-reference-doc` with the reference documentation for Warewulf 4 as PDF
 * The configuation files nodes.conf and warewulf.conf will be updated on upgrade and the unmodified configuration
 files will be saved as nodes.conf.4.5.x and warewulf.conf.4.5.x

- Summary of upstream changes:

 * New configuration upgrade system
 * Changes to the default profile
 * Renamed containers to (node) images
 * New kernel management system
 * Parallel overlay builds
 * Sprig functions in overlay templates
 * Improved network overlays
 * Nested profiles
 * Arbitrary 'resources' data in nodes.conf
 * NFS client configuration in nodes.conf
 * Emphatically optional syncuser
 * Improved network boot observability
 * Particularly significant changes, especially those affecting the user interface,
 are described in the release notes:

 + [link moved to references]");

  script_tag(name:"affected", value:"'warewulf4' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"warewulf4", rpm:"warewulf4~4.6.0~150500.6.34.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"warewulf4-dracut", rpm:"warewulf4-dracut~4.6.0~150500.6.34.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"warewulf4-man", rpm:"warewulf4-man~4.6.0~150500.6.34.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"warewulf4-overlay", rpm:"warewulf4-overlay~4.6.0~150500.6.34.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"warewulf4-overlay-slurm", rpm:"warewulf4-overlay-slurm~4.6.0~150500.6.34.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"warewulf4-reference-doc", rpm:"warewulf4-reference-doc~4.6.0~150500.6.34.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);

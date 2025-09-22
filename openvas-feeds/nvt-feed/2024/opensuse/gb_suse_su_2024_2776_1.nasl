# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856363");
  script_cve_id("CVE-2024-31080", "CVE-2024-31081", "CVE-2024-31083");
  script_tag(name:"creation_date", value:"2024-08-20 04:05:32 +0000 (Tue, 20 Aug 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-05 12:15:37 +0000 (Fri, 05 Apr 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:2776-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2776-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242776-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219892");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222310");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222442");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-August/019222.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dri3proto, presentproto, wayland-protocols, xwayland' package(s) announced via the SUSE-SU-2024:2776-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dri3proto, presentproto, wayland-protocols, xwayland fixes the following issues:

Changes in presentproto:

* update to version 1.4 (patch generated from xorgproto-2024.1 sources)

Changes in wayland-protocols:

- Update to version 1.36:

 * xdg-dialog: fix missing namespace in protocol name

- Changes from version 1.35:

 * cursor-shape-v1: Does not advertises the list of supported cursors
 * xdg-shell: add missing enum attribute to set_constraint_adjustment
 * xdg-shell: recommend against drawing decorations when tiled
 * tablet-v2: mark as stable
 * staging: add alpha-modifier protocol

- Update to 1.36

 * Fix to the xdg dialog protocol
 * tablet-v2 protocol is now stable
 * alpha-modifier: new protocol
 * Bug fix to the cursor shape documentation
 * The xdg-shell protocol now also explicitly recommends against
 drawing decorations outside of the window geometry when tiled

- Update to 1.34:

 * xdg-dialog: new protocol
 * xdg-toplevel-drag: new protocol
 * Fix typo in ext-foreign-toplevel-list-v1
 * tablet-v2: clarify that name/id events are optional
 * linux-drm-syncobj-v1: new protocol
 * linux-explicit-synchronization-v1: add linux-drm-syncobj note

- Update to version 1.33:

 * xdg-shell: Clarify what a toplevel by default includes
 * linux-dmabuf: sync changes from unstable to stable
 * linux-dmabuf: require all planes to use the same modifier
 * presentation-time: stop referring to Linux/glibc
 * security-context-v1: Make sandbox engine names use reverse-DNS
 * xdg-decoration: remove ambiguous wording in configure event
 * xdg-decoration: fix configure event summary
 * linux-dmabuf: mark as stable
 * linux-dmabuf: add note about implicit sync
 * security-context-v1: Document what can be done with the open
 sockets
 * security-context-v1: Document out of band metadata for flatpak

Changes in dri3proto:

* update to version 1.4 (patch generated from xorgproto-2024.1 sources)

Changes in xwayland:


- Update to bugfix release 24.1.1 for the current stable 24.1
 branch of Xwayland

 * xwayland: fix segment fault in `xwl_glamor_gbm_init_main_dev`
 * os: Explicitly include X11/Xmd.h for CARD32 definition to fix
 building on i686
 * present: On *BSD, epoll-shim is needed to emulate eventfd()
 * xwayland: Stop on first unmapped child
 * xwayland/window-buffers: Promote xwl_window_buffer
 * xwayland/window-buffers: Add xwl_window_buffer_release()
 * xwayland/glamor/gbm: Copy explicit sync code to GLAMOR/GBM
 * xwayland/window-buffers: Use synchronization from GLAMOR/GBM
 * xwayland/window-buffers: Do not always set syncpnts
 * xwayland/window-buffers: Move code to submit pixmaps
 * xwayland/window-buffers: Set syncpnts for all pixmaps
 * xwayland: Move xwl_window disposal to its own function
 * xwayland: Make sure we do not leak xwl_window on destroy
 * wayland/window-buffers: Move buffer disposal to its own function
 * xwayland/window-buffers: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'dri3proto, presentproto, wayland-protocols, xwayland' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"dri3proto-devel", rpm:"dri3proto-devel~1.2~150100.6.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"dri3proto-devel", rpm:"dri3proto-devel~1.2~150100.6.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"presentproto-devel", rpm:"presentproto-devel~1.3~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wayland-protocols-devel", rpm:"wayland-protocols-devel~1.36~150600.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xwayland", rpm:"xwayland~24.1.1~150600.5.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xwayland-devel", rpm:"xwayland-devel~24.1.1~150600.5.3.1", rls:"openSUSELeap15.6"))) {
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

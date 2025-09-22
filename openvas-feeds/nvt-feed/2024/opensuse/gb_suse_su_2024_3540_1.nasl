# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856547");
  script_cve_id("CVE-2023-45913", "CVE-2023-45919", "CVE-2023-45922");
  script_tag(name:"creation_date", value:"2024-10-09 04:03:38 +0000 (Wed, 09 Oct 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:3540-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3540-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243540-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222041");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222042");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-October/037160.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mesa' package(s) announced via the SUSE-SU-2024:3540-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for Mesa fixes the following issues:

- CVE-2023-45913: Fixed NULL pointer dereference via dri2GetGlxDrawableFromXDrawableId() (bsc#1222040)
- CVE-2023-45919: Fixed buffer over-read in glXQueryServerString() (bsc#1222041)
- CVE-2023-45922: Fixed segmentation violation in __glXGetDrawableAttribute() (bsc#1222042)");

  script_tag(name:"affected", value:"'Mesa' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"Mesa", rpm:"Mesa~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-32bit", rpm:"Mesa-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-KHR-devel", rpm:"Mesa-KHR-devel~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-devel", rpm:"Mesa-devel~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri", rpm:"Mesa-dri~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-32bit", rpm:"Mesa-dri-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-devel", rpm:"Mesa-dri-devel~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-nouveau", rpm:"Mesa-dri-nouveau~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-nouveau-32bit", rpm:"Mesa-dri-nouveau-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-vc4", rpm:"Mesa-dri-vc4~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-gallium", rpm:"Mesa-gallium~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-gallium-32bit", rpm:"Mesa-gallium-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL-devel", rpm:"Mesa-libEGL-devel~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL-devel-32bit", rpm:"Mesa-libEGL-devel-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL1", rpm:"Mesa-libEGL1~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL1-32bit", rpm:"Mesa-libEGL1-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL-devel", rpm:"Mesa-libGL-devel~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL-devel-32bit", rpm:"Mesa-libGL-devel-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL1", rpm:"Mesa-libGL1~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL1-32bit", rpm:"Mesa-libGL1-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGLESv1_CM-devel", rpm:"Mesa-libGLESv1_CM-devel~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGLESv1_CM-devel-32bit", rpm:"Mesa-libGLESv1_CM-devel-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGLESv2-devel", rpm:"Mesa-libGLESv2-devel~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGLESv2-devel-32bit", rpm:"Mesa-libGLESv2-devel-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGLESv3-devel", rpm:"Mesa-libGLESv3-devel~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libOpenCL", rpm:"Mesa-libOpenCL~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libd3d", rpm:"Mesa-libd3d~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libd3d-32bit", rpm:"Mesa-libd3d-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libd3d-devel", rpm:"Mesa-libd3d-devel~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libd3d-devel-32bit", rpm:"Mesa-libd3d-devel-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi-devel", rpm:"Mesa-libglapi-devel~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi-devel-32bit", rpm:"Mesa-libglapi-devel-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi0", rpm:"Mesa-libglapi0~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi0-32bit", rpm:"Mesa-libglapi0-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libva", rpm:"Mesa-libva~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-vulkan-device-select", rpm:"Mesa-vulkan-device-select~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-vulkan-device-select-32bit", rpm:"Mesa-vulkan-device-select-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-vulkan-overlay", rpm:"Mesa-vulkan-overlay~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-vulkan-overlay-32bit", rpm:"Mesa-vulkan-overlay-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOSMesa-devel", rpm:"libOSMesa-devel~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOSMesa-devel-32bit", rpm:"libOSMesa-devel-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOSMesa8", rpm:"libOSMesa8~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOSMesa8-32bit", rpm:"libOSMesa8-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm-devel", rpm:"libgbm-devel~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm-devel-32bit", rpm:"libgbm-devel-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1", rpm:"libgbm1~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1-32bit", rpm:"libgbm1-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_nouveau", rpm:"libvdpau_nouveau~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_nouveau-32bit", rpm:"libvdpau_nouveau-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_r600", rpm:"libvdpau_r600~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_r600-32bit", rpm:"libvdpau_r600-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_radeonsi", rpm:"libvdpau_radeonsi~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_radeonsi-32bit", rpm:"libvdpau_radeonsi-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_virtio_gpu", rpm:"libvdpau_virtio_gpu~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_virtio_gpu-32bit", rpm:"libvdpau_virtio_gpu-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_broadcom", rpm:"libvulkan_broadcom~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_freedreno", rpm:"libvulkan_freedreno~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_intel", rpm:"libvulkan_intel~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_intel-32bit", rpm:"libvulkan_intel-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_lvp", rpm:"libvulkan_lvp~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_radeon", rpm:"libvulkan_radeon~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_radeon-32bit", rpm:"libvulkan_radeon-32bit~23.3.4~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxatracker-devel", rpm:"libxatracker-devel~1.0.0~150600.83.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxatracker2", rpm:"libxatracker2~1.0.0~150600.83.3.1", rls:"openSUSELeap15.6"))) {
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

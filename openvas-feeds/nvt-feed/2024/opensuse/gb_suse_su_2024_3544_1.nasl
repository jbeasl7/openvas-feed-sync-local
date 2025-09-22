# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856541");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-45913", "CVE-2023-45919", "CVE-2023-45922");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-10-09 04:00:41 +0000 (Wed, 09 Oct 2024)");
  script_name("openSUSE: Security Advisory for Mesa (SUSE-SU-2024:3544-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3544-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BKVX7SCC5XW3DWVEZ5LNYOX4YEUDPINQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mesa'
  package(s) announced via the SUSE-SU-2024:3544-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for Mesa fixes the following issues:

  * CVE-2023-45919: Fixed buffer over-read in glXQueryServerString()
      (bsc#1222041).

  * CVE-2023-45913: Fixed NULL pointer dereference via
      dri2GetGlxDrawableFromXDrawableId() (bsc#1222040).

  * CVE-2023-45922: Fixed segmentation violation in __glXGetDrawableAttribute()
      (bsc#CVE-2023-45922).");

  script_tag(name:"affected", value:"'Mesa' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGLESv1_CM-devel", rpm:"Mesa-libGLESv1_CM-devel~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-KHR-devel", rpm:"Mesa-KHR-devel~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOSMesa8-debuginfo", rpm:"libOSMesa8-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL1", rpm:"Mesa-libEGL1~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm-devel", rpm:"libgbm-devel~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi0", rpm:"Mesa-libglapi0~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGLESv3-devel", rpm:"Mesa-libGLESv3-devel~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL1", rpm:"Mesa-libGL1~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-devel", rpm:"Mesa-devel~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-debuginfo", rpm:"Mesa-dri-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1-debuginfo", rpm:"libgbm1-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL1-debuginfo", rpm:"Mesa-libEGL1-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL1-debuginfo", rpm:"Mesa-libGL1-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOSMesa8", rpm:"libOSMesa8~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi0-debuginfo", rpm:"Mesa-libglapi0-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGLESv2-devel", rpm:"Mesa-libGLESv2-devel~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa", rpm:"Mesa~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL-devel", rpm:"Mesa-libGL-devel~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-devel", rpm:"Mesa-dri-devel~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOSMesa-devel", rpm:"libOSMesa-devel~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri", rpm:"Mesa-dri~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi-devel", rpm:"Mesa-libglapi-devel~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-drivers-debugsource", rpm:"Mesa-drivers-debugsource~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL-devel", rpm:"Mesa-libEGL-devel~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1", rpm:"libgbm1~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-debugsource", rpm:"Mesa-debugsource~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_intel-32bit", rpm:"libvulkan_intel-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-vulkan-overlay-32bit", rpm:"Mesa-vulkan-overlay-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm-devel-32bit", rpm:"libgbm-devel-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1-32bit-debuginfo", rpm:"libgbm1-32bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_radeon-32bit-debuginfo", rpm:"libvulkan_radeon-32bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-32bit", rpm:"Mesa-dri-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_radeonsi-32bit", rpm:"libvdpau_radeonsi-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1-32bit", rpm:"libgbm1-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC_nouveau-32bit", rpm:"libXvMC_nouveau-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL-devel-32bit", rpm:"Mesa-libGL-devel-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libd3d-devel-32bit", rpm:"Mesa-libd3d-devel-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi-devel-32bit", rpm:"Mesa-libglapi-devel-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGLESv2-devel-32bit", rpm:"Mesa-libGLESv2-devel-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-32bit-debuginfo", rpm:"Mesa-dri-32bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGLESv1_CM-devel-32bit", rpm:"Mesa-libGLESv1_CM-devel-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC_nouveau-32bit-debuginfo", rpm:"libXvMC_nouveau-32bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_radeon-32bit", rpm:"libvulkan_radeon-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libd3d-32bit", rpm:"Mesa-libd3d-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL1-32bit", rpm:"Mesa-libGL1-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi0-32bit-debuginfo", rpm:"Mesa-libglapi0-32bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_r600-32bit-debuginfo", rpm:"libvdpau_r600-32bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_radeonsi-32bit-debuginfo", rpm:"libvdpau_radeonsi-32bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_r600-32bit", rpm:"libvdpau_r600-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-vulkan-overlay-32bit-debuginfo", rpm:"Mesa-vulkan-overlay-32bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_nouveau-32bit-debuginfo", rpm:"libvdpau_nouveau-32bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOSMesa-devel-32bit", rpm:"libOSMesa-devel-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOSMesa8-32bit", rpm:"libOSMesa8-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-nouveau-32bit-debuginfo", rpm:"Mesa-dri-nouveau-32bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-32bit", rpm:"Mesa-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_r300-32bit-debuginfo", rpm:"libvdpau_r300-32bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_r300-32bit", rpm:"libvdpau_r300-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL1-32bit", rpm:"Mesa-libEGL1-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL1-32bit-debuginfo", rpm:"Mesa-libGL1-32bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi0-32bit", rpm:"Mesa-libglapi0-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-gallium-32bit", rpm:"Mesa-gallium-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL-devel-32bit", rpm:"Mesa-libEGL-devel-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-nouveau-32bit", rpm:"Mesa-dri-nouveau-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-vulkan-device-select-32bit-debuginfo", rpm:"Mesa-vulkan-device-select-32bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-vulkan-device-select-32bit", rpm:"Mesa-vulkan-device-select-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_nouveau-32bit", rpm:"libvdpau_nouveau-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-gallium-32bit-debuginfo", rpm:"Mesa-gallium-32bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC_r600-32bit", rpm:"libXvMC_r600-32bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_intel-32bit-debuginfo", rpm:"libvulkan_intel-32bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL1-32bit-debuginfo", rpm:"Mesa-libEGL1-32bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOSMesa8-32bit-debuginfo", rpm:"libOSMesa8-32bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libd3d-32bit-debuginfo", rpm:"Mesa-libd3d-32bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC_r600-32bit-debuginfo", rpm:"libXvMC_r600-32bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_nouveau-debuginfo", rpm:"libvdpau_nouveau-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_r300", rpm:"libvdpau_r300~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_radeonsi", rpm:"libvdpau_radeonsi~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libva-debuginfo", rpm:"Mesa-libva-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_r600-debuginfo", rpm:"libvdpau_r600-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC_nouveau-debuginfo", rpm:"libXvMC_nouveau-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_r600", rpm:"libvdpau_r600~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_r300-debuginfo", rpm:"libvdpau_r300-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC_r600", rpm:"libXvMC_r600~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_radeonsi-debuginfo", rpm:"libvdpau_radeonsi-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC_nouveau", rpm:"libXvMC_nouveau~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libOpenCL", rpm:"Mesa-libOpenCL~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxatracker2-debuginfo", rpm:"libxatracker2-debuginfo~1.0.0~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC_r600-debuginfo", rpm:"libXvMC_r600-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libva", rpm:"Mesa-libva~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-nouveau", rpm:"Mesa-dri-nouveau~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libOpenCL-debuginfo", rpm:"Mesa-libOpenCL-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxatracker2", rpm:"libxatracker2~1.0.0~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-gallium-debuginfo", rpm:"Mesa-gallium-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxatracker-devel", rpm:"libxatracker-devel~1.0.0~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-gallium", rpm:"Mesa-gallium~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-nouveau-debuginfo", rpm:"Mesa-dri-nouveau-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_nouveau", rpm:"libvdpau_nouveau~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_lvp", rpm:"libvulkan_lvp~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libVulkan-devel", rpm:"Mesa-libVulkan-devel~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-vulkan-overlay", rpm:"Mesa-vulkan-overlay~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libd3d-devel", rpm:"Mesa-libd3d-devel~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-vulkan-overlay-debuginfo", rpm:"Mesa-vulkan-overlay-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_lvp-debuginfo", rpm:"libvulkan_lvp-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libd3d-debuginfo", rpm:"Mesa-libd3d-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_radeon-debuginfo", rpm:"libvulkan_radeon-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-vulkan-device-select", rpm:"Mesa-vulkan-device-select~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libd3d", rpm:"Mesa-libd3d~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_radeon", rpm:"libvulkan_radeon~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-vulkan-device-select-debuginfo", rpm:"Mesa-vulkan-device-select-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_intel", rpm:"libvulkan_intel~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_intel-debuginfo", rpm:"libvulkan_intel-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC_nouveau-64bit", rpm:"libXvMC_nouveau-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_radeonsi-64bit", rpm:"libvdpau_radeonsi-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_r600-64bit", rpm:"libvdpau_r600-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOSMesa8-64bit", rpm:"libOSMesa8-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL-devel-64bit", rpm:"Mesa-libEGL-devel-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-64bit", rpm:"Mesa-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi0-64bit-debuginfo", rpm:"Mesa-libglapi0-64bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC_r600-64bit", rpm:"libXvMC_r600-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_r300-64bit-debuginfo", rpm:"libvdpau_r300-64bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGLESv1_CM-devel-64bit", rpm:"Mesa-libGLESv1_CM-devel-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_nouveau-64bit-debuginfo", rpm:"libvdpau_nouveau-64bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL-devel-64bit", rpm:"Mesa-libGL-devel-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_radeonsi-64bit-debuginfo", rpm:"libvdpau_radeonsi-64bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_radeon-64bit-debuginfo", rpm:"libvulkan_radeon-64bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libd3d-devel-64bit", rpm:"Mesa-libd3d-devel-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC_r600-64bit-debuginfo", rpm:"libXvMC_r600-64bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm-devel-64bit", rpm:"libgbm-devel-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1-64bit", rpm:"libgbm1-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-vc4-64bit", rpm:"Mesa-dri-vc4-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-vc4-64bit-debuginfo", rpm:"Mesa-dri-vc4-64bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_r600-64bit-debuginfo", rpm:"libvdpau_r600-64bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL1-64bit", rpm:"Mesa-libGL1-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOSMesa-devel-64bit", rpm:"libOSMesa-devel-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGLESv2-devel-64bit", rpm:"Mesa-libGLESv2-devel-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOSMesa8-64bit-debuginfo", rpm:"libOSMesa8-64bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL1-64bit-debuginfo", rpm:"Mesa-libGL1-64bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi-devel-64bit", rpm:"Mesa-libglapi-devel-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL1-64bit", rpm:"Mesa-libEGL1-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi0-64bit", rpm:"Mesa-libglapi0-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_radeon-64bit", rpm:"libvulkan_radeon-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-64bit", rpm:"Mesa-dri-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_r300-64bit", rpm:"libvdpau_r300-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-nouveau-64bit", rpm:"Mesa-dri-nouveau-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL1-64bit-debuginfo", rpm:"Mesa-libEGL1-64bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-vulkan-overlay-64bit-debuginfo", rpm:"Mesa-vulkan-overlay-64bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-64bit-debuginfo", rpm:"Mesa-dri-64bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-vulkan-device-select-64bit", rpm:"Mesa-vulkan-device-select-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-nouveau-64bit-debuginfo", rpm:"Mesa-dri-nouveau-64bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-gallium-64bit-debuginfo", rpm:"Mesa-gallium-64bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-vulkan-device-select-64bit-debuginfo", rpm:"Mesa-vulkan-device-select-64bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libd3d-64bit-debuginfo", rpm:"Mesa-libd3d-64bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-vulkan-overlay-64bit", rpm:"Mesa-vulkan-overlay-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1-64bit-debuginfo", rpm:"libgbm1-64bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libd3d-64bit", rpm:"Mesa-libd3d-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvdpau_nouveau-64bit", rpm:"libvdpau_nouveau-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-gallium-64bit", rpm:"Mesa-gallium-64bit~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC_nouveau-64bit-debuginfo", rpm:"libXvMC_nouveau-64bit-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_freedreno", rpm:"libvulkan_freedreno~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_broadcom", rpm:"libvulkan_broadcom~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-vc4", rpm:"Mesa-dri-vc4~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-dri-vc4-debuginfo", rpm:"Mesa-dri-vc4-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_freedreno-debuginfo", rpm:"libvulkan_freedreno-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvulkan_broadcom-debuginfo", rpm:"libvulkan_broadcom-debuginfo~21.2.4~150400.68.15.1", rls:"openSUSELeap15.4"))) {
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
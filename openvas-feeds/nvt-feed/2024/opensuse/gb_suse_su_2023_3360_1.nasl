# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833857");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-20569");
  script_tag(name:"cvss_base", value:"3.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-14 17:42:56 +0000 (Thu, 14 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:39:33 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for kernel (SUSE-SU-2023:3360-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeapMicro5\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3360-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/Y2HXEJLWMHTO4MEEYCTYH7GYM5LENAI2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the SUSE-SU-2023:3360-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kernel-firmware fixes the following issues:

  * CVE-2023-20569: Fixed AMD 19h ucode to mitigate a side channel vulnerability
      in some of the AMD CPUs. (bsc#1213287)

  ## Special Instructions and Notes:

  * Please reboot the system after installing this update.

  ##");

  script_tag(name:"affected", value:"'kernel' package(s) on openSUSE Leap 15.4, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mellanox-20220509", rpm:"kernel-firmware-mellanox-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-iwlwifi-20220509", rpm:"kernel-firmware-iwlwifi-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-media-20220509", rpm:"kernel-firmware-media-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mwifiex-20220509", rpm:"kernel-firmware-mwifiex-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-amd-20220509", rpm:"ucode-amd-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-realtek-20220509", rpm:"kernel-firmware-realtek-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-atheros-20220509", rpm:"kernel-firmware-atheros-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-i915-20220509", rpm:"kernel-firmware-i915-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-liquidio-20220509", rpm:"kernel-firmware-liquidio-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ti-20220509", rpm:"kernel-firmware-ti-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-chelsio-20220509", rpm:"kernel-firmware-chelsio-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-sound-20220509", rpm:"kernel-firmware-sound-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-all-20220509", rpm:"kernel-firmware-all-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bluetooth-20220509", rpm:"kernel-firmware-bluetooth-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-qlogic-20220509", rpm:"kernel-firmware-qlogic-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-radeon-20220509", rpm:"kernel-firmware-radeon-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-qcom-20220509", rpm:"kernel-firmware-qcom-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-platform-20220509", rpm:"kernel-firmware-platform-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mediatek-20220509", rpm:"kernel-firmware-mediatek-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath11k-20220509", rpm:"kernel-firmware-ath11k-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-20220509", rpm:"kernel-firmware-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nvidia-20220509", rpm:"kernel-firmware-nvidia-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-usb-network-20220509", rpm:"kernel-firmware-usb-network-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nfp-20220509", rpm:"kernel-firmware-nfp-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-prestera-20220509", rpm:"kernel-firmware-prestera-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-marvell-20220509", rpm:"kernel-firmware-marvell-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bnx2-20220509", rpm:"kernel-firmware-bnx2-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-amdgpu-20220509", rpm:"kernel-firmware-amdgpu-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-serial-20220509", rpm:"kernel-firmware-serial-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-brcm-20220509", rpm:"kernel-firmware-brcm-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-network-20220509", rpm:"kernel-firmware-network-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath10k-20220509", rpm:"kernel-firmware-ath10k-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ueagle-20220509", rpm:"kernel-firmware-ueagle-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-intel-20220509", rpm:"kernel-firmware-intel-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-dpaa2-20220509", rpm:"kernel-firmware-dpaa2-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mellanox-20220509", rpm:"kernel-firmware-mellanox-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-iwlwifi-20220509", rpm:"kernel-firmware-iwlwifi-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-media-20220509", rpm:"kernel-firmware-media-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mwifiex-20220509", rpm:"kernel-firmware-mwifiex-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-amd-20220509", rpm:"ucode-amd-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-realtek-20220509", rpm:"kernel-firmware-realtek-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-atheros-20220509", rpm:"kernel-firmware-atheros-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-i915-20220509", rpm:"kernel-firmware-i915-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-liquidio-20220509", rpm:"kernel-firmware-liquidio-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ti-20220509", rpm:"kernel-firmware-ti-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-chelsio-20220509", rpm:"kernel-firmware-chelsio-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-sound-20220509", rpm:"kernel-firmware-sound-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-all-20220509", rpm:"kernel-firmware-all-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bluetooth-20220509", rpm:"kernel-firmware-bluetooth-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-qlogic-20220509", rpm:"kernel-firmware-qlogic-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-radeon-20220509", rpm:"kernel-firmware-radeon-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-qcom-20220509", rpm:"kernel-firmware-qcom-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-platform-20220509", rpm:"kernel-firmware-platform-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mediatek-20220509", rpm:"kernel-firmware-mediatek-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath11k-20220509", rpm:"kernel-firmware-ath11k-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-20220509", rpm:"kernel-firmware-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nvidia-20220509", rpm:"kernel-firmware-nvidia-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-usb-network-20220509", rpm:"kernel-firmware-usb-network-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nfp-20220509", rpm:"kernel-firmware-nfp-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-prestera-20220509", rpm:"kernel-firmware-prestera-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-marvell-20220509", rpm:"kernel-firmware-marvell-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bnx2-20220509", rpm:"kernel-firmware-bnx2-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-amdgpu-20220509", rpm:"kernel-firmware-amdgpu-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-serial-20220509", rpm:"kernel-firmware-serial-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-brcm-20220509", rpm:"kernel-firmware-brcm-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-network-20220509", rpm:"kernel-firmware-network-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath10k-20220509", rpm:"kernel-firmware-ath10k-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ueagle-20220509", rpm:"kernel-firmware-ueagle-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-intel-20220509", rpm:"kernel-firmware-intel-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-dpaa2-20220509", rpm:"kernel-firmware-dpaa2-20220509~150400.4.22.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mellanox-20220509", rpm:"kernel-firmware-mellanox-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-iwlwifi-20220509", rpm:"kernel-firmware-iwlwifi-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-media-20220509", rpm:"kernel-firmware-media-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mwifiex-20220509", rpm:"kernel-firmware-mwifiex-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-amd-20220509", rpm:"ucode-amd-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-realtek-20220509", rpm:"kernel-firmware-realtek-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-atheros-20220509", rpm:"kernel-firmware-atheros-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-i915-20220509", rpm:"kernel-firmware-i915-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-liquidio-20220509", rpm:"kernel-firmware-liquidio-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ti-20220509", rpm:"kernel-firmware-ti-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-chelsio-20220509", rpm:"kernel-firmware-chelsio-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-sound-20220509", rpm:"kernel-firmware-sound-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-all-20220509", rpm:"kernel-firmware-all-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bluetooth-20220509", rpm:"kernel-firmware-bluetooth-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-qlogic-20220509", rpm:"kernel-firmware-qlogic-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-radeon-20220509", rpm:"kernel-firmware-radeon-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-qcom-20220509", rpm:"kernel-firmware-qcom-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-platform-20220509", rpm:"kernel-firmware-platform-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mediatek-20220509", rpm:"kernel-firmware-mediatek-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath11k-20220509", rpm:"kernel-firmware-ath11k-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-usb-network-20220509", rpm:"kernel-firmware-usb-network-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nvidia-20220509", rpm:"kernel-firmware-nvidia-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nfp-20220509", rpm:"kernel-firmware-nfp-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-prestera-20220509", rpm:"kernel-firmware-prestera-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-marvell-20220509", rpm:"kernel-firmware-marvell-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bnx2-20220509", rpm:"kernel-firmware-bnx2-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-amdgpu-20220509", rpm:"kernel-firmware-amdgpu-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-serial-20220509", rpm:"kernel-firmware-serial-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-brcm-20220509", rpm:"kernel-firmware-brcm-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-network-20220509", rpm:"kernel-firmware-network-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath10k-20220509", rpm:"kernel-firmware-ath10k-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ueagle-20220509", rpm:"kernel-firmware-ueagle-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-intel-20220509", rpm:"kernel-firmware-intel-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-dpaa2-20220509", rpm:"kernel-firmware-dpaa2-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mellanox-20220509", rpm:"kernel-firmware-mellanox-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-iwlwifi-20220509", rpm:"kernel-firmware-iwlwifi-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-media-20220509", rpm:"kernel-firmware-media-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mwifiex-20220509", rpm:"kernel-firmware-mwifiex-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-amd-20220509", rpm:"ucode-amd-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-realtek-20220509", rpm:"kernel-firmware-realtek-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-atheros-20220509", rpm:"kernel-firmware-atheros-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-i915-20220509", rpm:"kernel-firmware-i915-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-liquidio-20220509", rpm:"kernel-firmware-liquidio-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ti-20220509", rpm:"kernel-firmware-ti-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-chelsio-20220509", rpm:"kernel-firmware-chelsio-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-sound-20220509", rpm:"kernel-firmware-sound-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-all-20220509", rpm:"kernel-firmware-all-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bluetooth-20220509", rpm:"kernel-firmware-bluetooth-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-qlogic-20220509", rpm:"kernel-firmware-qlogic-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-radeon-20220509", rpm:"kernel-firmware-radeon-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-qcom-20220509", rpm:"kernel-firmware-qcom-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-platform-20220509", rpm:"kernel-firmware-platform-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mediatek-20220509", rpm:"kernel-firmware-mediatek-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath11k-20220509", rpm:"kernel-firmware-ath11k-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-usb-network-20220509", rpm:"kernel-firmware-usb-network-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nvidia-20220509", rpm:"kernel-firmware-nvidia-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nfp-20220509", rpm:"kernel-firmware-nfp-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-prestera-20220509", rpm:"kernel-firmware-prestera-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-marvell-20220509", rpm:"kernel-firmware-marvell-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bnx2-20220509", rpm:"kernel-firmware-bnx2-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-amdgpu-20220509", rpm:"kernel-firmware-amdgpu-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-serial-20220509", rpm:"kernel-firmware-serial-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-brcm-20220509", rpm:"kernel-firmware-brcm-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-network-20220509", rpm:"kernel-firmware-network-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath10k-20220509", rpm:"kernel-firmware-ath10k-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ueagle-20220509", rpm:"kernel-firmware-ueagle-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-intel-20220509", rpm:"kernel-firmware-intel-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-dpaa2-20220509", rpm:"kernel-firmware-dpaa2-20220509~150400.4.22.1", rls:"openSUSELeapMicro5.4"))) {
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
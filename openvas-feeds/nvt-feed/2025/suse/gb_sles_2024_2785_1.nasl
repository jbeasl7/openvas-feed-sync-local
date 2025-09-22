# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2785.1");
  script_cve_id("CVE-2023-38417", "CVE-2023-47210");
  script_tag(name:"creation_date", value:"2025-06-04 14:43:37 +0000 (Wed, 04 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2785-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2785-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242785-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225601");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-August/036336.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-firmware' package(s) announced via the SUSE-SU-2024:2785-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kernel-firmware fixes the following issues:

Update to version 20240728:

* amdgpu: update DMCUB to v0.0.227.0 for DCN35 and DCN351
* Revert 'iwlwifi: update ty/So/Ma firmwares for core89-58 release'
* linux-firmware: update firmware for MT7922 WiFi device
* linux-firmware: update firmware for MT7921 WiFi device
* linux-firmware: update firmware for mediatek bluetooth chip (MT7922)
* linux-firmware: update firmware for mediatek bluetooth chip (MT7921)
* iwlwifi: add gl FW for core89-58 release
* iwlwifi: update ty/So/Ma firmwares for core89-58 release
* iwlwifi: update cc/Qu/QuZ firmwares for core89-58 release
* mediatek: Update mt8195 SOF firmware and sof-tplg
* ASoC: tas2781: fix the license issue for tas781 firmware
* rtl_bt: Update RTL8852B BT USB FW to 0x048F_4008
* i915: Update Xe2LPD DMC to v2.21
* qcom: move signed x1e80100 signed firmware to the SoC subdir
* qcom: add video firmware file for vpu-3.0
* intel: avs: Add topology file for I2S Analog Devices 4567
* intel: avs: Add topology file for I2S Nuvoton 8825
* intel: avs: Add topology file for I2S Maxim 98927
* intel: avs: Add topology file for I2S Maxim 98373
* intel: avs: Add topology file for I2S Maxim 98357a
* intel: avs: Add topology file for I2S Dialog 7219
* intel: avs: Add topology file for I2S Realtek 5663
* intel: avs: Add topology file for I2S Realtek 5640
* intel: avs: Add topology file for I2S Realtek 5514
* intel: avs: Add topology file for I2S Realtek 298
* intel: avs: Add topology file for I2S Realtek 286
* intel: avs: Add topology file for I2S Realtek 274
* intel: avs: Add topology file for Digital Microphone Array
* intel: avs: Add topology file for HDMI codecs
* intel: avs: Add topology file for HDAudio codecs
* intel: avs: Update AudioDSP base firmware for APL-based platforms");

  script_tag(name:"affected", value:"'kernel-firmware' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-all", rpm:"kernel-firmware-all~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-amdgpu", rpm:"kernel-firmware-amdgpu~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath10k", rpm:"kernel-firmware-ath10k~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath11k", rpm:"kernel-firmware-ath11k~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath12k", rpm:"kernel-firmware-ath12k~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-atheros", rpm:"kernel-firmware-atheros~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bluetooth", rpm:"kernel-firmware-bluetooth~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bnx2", rpm:"kernel-firmware-bnx2~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-brcm", rpm:"kernel-firmware-brcm~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-chelsio", rpm:"kernel-firmware-chelsio~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-dpaa2", rpm:"kernel-firmware-dpaa2~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-i915", rpm:"kernel-firmware-i915~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-intel", rpm:"kernel-firmware-intel~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-iwlwifi", rpm:"kernel-firmware-iwlwifi~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-liquidio", rpm:"kernel-firmware-liquidio~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-marvell", rpm:"kernel-firmware-marvell~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-media", rpm:"kernel-firmware-media~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mediatek", rpm:"kernel-firmware-mediatek~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mellanox", rpm:"kernel-firmware-mellanox~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mwifiex", rpm:"kernel-firmware-mwifiex~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-network", rpm:"kernel-firmware-network~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nfp", rpm:"kernel-firmware-nfp~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nvidia", rpm:"kernel-firmware-nvidia~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-platform", rpm:"kernel-firmware-platform~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-prestera", rpm:"kernel-firmware-prestera~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-qcom", rpm:"kernel-firmware-qcom~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-qlogic", rpm:"kernel-firmware-qlogic~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-radeon", rpm:"kernel-firmware-radeon~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-realtek", rpm:"kernel-firmware-realtek~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-serial", rpm:"kernel-firmware-serial~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-sound", rpm:"kernel-firmware-sound~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ti", rpm:"kernel-firmware-ti~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ueagle", rpm:"kernel-firmware-ueagle~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-usb-network", rpm:"kernel-firmware-usb-network~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-amd", rpm:"ucode-amd~20240728~150600.3.6.1", rls:"SLES15.0SP6"))) {
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

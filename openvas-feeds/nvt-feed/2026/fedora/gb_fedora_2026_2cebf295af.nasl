# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.2991019810229597102");
  script_tag(name:"creation_date", value:"2026-01-15 04:21:16 +0000 (Thu, 15 Jan 2026)");
  script_version("2026-01-15T05:47:46+0000");
  script_tag(name:"last_modification", value:"2026-01-15 05:47:46 +0000 (Thu, 15 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-2cebf295af)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-2cebf295af");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-2cebf295af");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2341650");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2390638");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2419812");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2420062");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-firmware' package(s) announced via the FEDORA-2026-2cebf295af advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 20260110:

* update firmware for MT7925 WiFi device
* mediatek MT7925: update bluetooth firmware to 20260106153314
* mediatek MT7920: update bluetooth firmware to 20260105151350
* mediatek MT7922: update bluetooth firmware to 20260106153735
* update firmware for MT7922 WiFi device
* Mellanox: Add new mlxsw_spectrum firmware xx.2016.3900
* amdgpu: Update dcn314, dcn315 firmware to 0.1.42.0
* qcom: Update DSP firmware for sa8775 platform
* QCA: Add Bluetooth firmware for QCC2072 uart interface
* i915: Xe3p_LPD DMC v2.33
* qcom: Update DSP firmware for qcs8300 platform
* update firmware for MT7920 WiFi device
* qcom: Update aic100 firmware files
* qca: Update Bluetooth WCN6750 1.1.3-00100 firmware to 1.1.3-00105
* firmware: Revert kernel_boot.elf due to license compliance issue
* add firmware for an8811hb 2.5G ethernet phy
* i915: Xe3LPD_3002 DMC v2.28
* i915: Xe3LPD DMC v2.33
* intel_vpu: Add firmware for 50xx NPUs and update older ones
* Update AMD SEV firmware
* amdgpu: DMCUB updates for various ASICs
* qcom: venus-5.4: fix ELF segment alignment to 4 bytes
* mediatek MT7925: update bluetooth firmware to 20251210093205
* update firmware for MT7925 WiFi device
* rcar_gen4_pcie: add firmware for Renesas R-Car Gen4 PCIe controller
* qcom: Update CDSP firmware for qcm6490 platform
* rtl_bt: Update RTL8852BT/RTL8852BE-VT BT USB FW to 0x488C_DB55
* iwlwifi: Add firmware file for Intel Scorpius core
* rtw89: 8852b: update fw to v0.29.29.15
* cirrus: cs35l41: Update firmware and tuning for various HP laptops
* cirrus: cs35l41: Add support for new HP Clipper laptop
* qcom: drop compatibility a640_zap.mdt symlink
* qcom: add version for a530v3_gpmu.fw2
* xe: Update GUC to v70.55.3 for BMG, PTL
* iwlwifi: add Bz/Sc FW for core101-82 release
* iwlwifi: Add Sc/Gf firmware for core101-82 release
* iwlwifi: update ty/So/Ma firmwares for core101-82 release
* iwlwifi: update cc/Qu/QuZ firmwares for core101-82 release
* amdgpu: DMCUB updates for various ASICs
* qcom: Add firmwares for sm8150/sm8450/sm8550/sm8650/sm8750 GPUs
* ath10k: WCN3990 hw1.0: update board-2.bin
* ath10k: QCA9888 hw2.0: update board-2.bin
* ath10k: QCA4019 hw1.0: update board-2.bin
* cirrus: cs35l41: Add support for new HP laptops
* Revert 'amdgpu: update GC 11.5.0 firmware'
* Update amd-ucode copyright information
* Update AMD cpu microcode
* Update firmware file for Intel Scorpius core
* Update firmware file for Intel BlazarIGfP core
* Update firmware file for Intel BlazarI core
* Update firmware file for Intel BlazarU-HrPGfP core
* Update firmware file for Intel BlazarU core
* ath11k: QCA6698AQ hw2.1: update to WLAN.HSP.1.1-04866-QCAHSPSWPL_V1_V2_SILICONZ_IOE-1
* ath11k: QCA2066 hw2.1: update board-2.bin
* qcom: update ADSP firmware for x1e80100 platform, change the license
* qcom: reorder ADSP, CDSP firmware entries for qcs8300 in WHENCE
* Reapply 'amdgpu: update SMU 14.0.3 firmware'
* Revert 'amdgpu: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-firmware' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"amd-gpu-firmware", rpm:"amd-gpu-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"amd-ucode-firmware", rpm:"amd-ucode-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"atheros-firmware", rpm:"atheros-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"brcmfmac-firmware", rpm:"brcmfmac-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cirrus-audio-firmware", rpm:"cirrus-audio-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dvb-firmware", rpm:"dvb-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"intel-audio-firmware", rpm:"intel-audio-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"intel-gpu-firmware", rpm:"intel-gpu-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"intel-vsc-firmware", rpm:"intel-vsc-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlegacy-firmware", rpm:"iwlegacy-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlwifi-dvm-firmware", rpm:"iwlwifi-dvm-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlwifi-mld-firmware", rpm:"iwlwifi-mld-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlwifi-mvm-firmware", rpm:"iwlwifi-mvm-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libertas-firmware", rpm:"libertas-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linux-firmware", rpm:"linux-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linux-firmware-whence", rpm:"linux-firmware-whence~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liquidio-firmware", rpm:"liquidio-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediatek-firmware", rpm:"mediatek-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlxsw_spectrum-firmware", rpm:"mlxsw_spectrum-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mrvlprestera-firmware", rpm:"mrvlprestera-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mt7xxx-firmware", rpm:"mt7xxx-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netronome-firmware", rpm:"netronome-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-gpu-firmware", rpm:"nvidia-gpu-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nxpwireless-firmware", rpm:"nxpwireless-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qcom-accel-firmware", rpm:"qcom-accel-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qcom-firmware", rpm:"qcom-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qcom-wwan-firmware", rpm:"qcom-wwan-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qed-firmware", rpm:"qed-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"realtek-firmware", rpm:"realtek-firmware~20260110~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiwilink-firmware", rpm:"tiwilink-firmware~20260110~1.fc43", rls:"FC43"))) {
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

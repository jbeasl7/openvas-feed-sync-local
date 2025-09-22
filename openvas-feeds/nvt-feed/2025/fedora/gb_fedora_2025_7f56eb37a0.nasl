# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.7102561019837970");
  script_cve_id("CVE-2023-31355", "CVE-2024-21978");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-26 19:13:34 +0000 (Tue, 26 Nov 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2025-7f56eb37a0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-7f56eb37a0");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-7f56eb37a0");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2332762");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2332763");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2332764");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2332765");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2337005");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-firmware' package(s) announced via the FEDORA-2025-7f56eb37a0 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to upstream 20250311:

* amdgpu: many firmware updates
* qcom: Update gpu firmwares for qcs8300 chipset
* add firmware for qat_420xx devices
* amdgpu: DMCUB updates for various ASICs
* i915: Update Xe3LPD DMC to v2.20
* update firmware for MT7920/MT7925 WiFi device
* mediatek MT7920/MT7925 bluetooth firmware update
* Update firmware file for Intel BlazarI/BlazarU core
* intel_vpu: Add firmware for 37xx and 40xx NPUs
* QCA: Add Bluetooth firmwares for QCA2066 with USB transport
* QCA: Add two bluetooth firmware nvm files for QCA2066
* QCA: Update Bluetooth QCA2066 firmware to 2.1.0-00653
* QCA: Update Bluetooth WCN685x 2.1 firmware to 2.1.0-00653
* cirrus: cs35l41: Add firmware and tuning for ASUS Commercial/Consumer laptops
* ASoC: tas2781: Update dsp firmware for Gemtree project
* xe: Update GUC to v70.40.2 for BMG, LNL
* cirrus: cs35l41: Add firmware and tunings for CS35L41 driver for Steam Deck
* ath11k: QCN9074 hw1.0: update to WLAN.HK.2.9.0.1-02175-QCAHKSWPL_SILICONZ-2
* ath11k: QCA6698AQ hw2.1: update to WLAN.HSP.1.1-04604-QCAHSPSWPL_V1_V2_SILICONZ_IOE-1
* ath11k: QCA6698AQ hw2.1: update board-2.bin
* rtw89: 8852bt: update fw to v0.29.122.0 and BB parameter to 07
* Update AMD SEV firmware
* qca: update WCN3988 firmware
* amdgpu: Update ISP FW for isp v4.1.1
* qcom: add firmware for Adreno A225
* cirrus: cs35l56: Add / update firmware for Cirrus CS35L56 for ASUS/Dell/HP/Lenovo laptops
* update firmware for en8811h 2.5G ethernet phy
* ASoC: tas2781: Change regbin firmwares for single device");

  script_tag(name:"affected", value:"'linux-firmware' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"amd-gpu-firmware", rpm:"amd-gpu-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"amd-ucode-firmware", rpm:"amd-ucode-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"atheros-firmware", rpm:"atheros-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"brcmfmac-firmware", rpm:"brcmfmac-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cirrus-audio-firmware", rpm:"cirrus-audio-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dvb-firmware", rpm:"dvb-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"intel-audio-firmware", rpm:"intel-audio-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"intel-gpu-firmware", rpm:"intel-gpu-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"intel-vsc-firmware", rpm:"intel-vsc-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlegacy-firmware", rpm:"iwlegacy-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlwifi-dvm-firmware", rpm:"iwlwifi-dvm-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlwifi-mvm-firmware", rpm:"iwlwifi-mvm-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libertas-firmware", rpm:"libertas-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linux-firmware", rpm:"linux-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linux-firmware-whence", rpm:"linux-firmware-whence~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liquidio-firmware", rpm:"liquidio-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlxsw_spectrum-firmware", rpm:"mlxsw_spectrum-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mrvlprestera-firmware", rpm:"mrvlprestera-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mt7xxx-firmware", rpm:"mt7xxx-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netronome-firmware", rpm:"netronome-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-gpu-firmware", rpm:"nvidia-gpu-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nxpwireless-firmware", rpm:"nxpwireless-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qcom-firmware", rpm:"qcom-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qed-firmware", rpm:"qed-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"realtek-firmware", rpm:"realtek-firmware~20250311~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiwilink-firmware", rpm:"tiwilink-firmware~20250311~1.fc41", rls:"FC41"))) {
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

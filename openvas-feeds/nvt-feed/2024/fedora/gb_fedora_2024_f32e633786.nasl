# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.10232101633786");
  script_cve_id("CVE-2023-31315");
  script_tag(name:"creation_date", value:"2024-09-11 04:13:54 +0000 (Wed, 11 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-f32e633786)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-f32e633786");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-f32e633786");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2306155");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-firmware' package(s) announced via the FEDORA-2024-f32e633786 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to upstream 20240909:

* i915: Update MTL DMC v2.23
* cirrus: cs35l56: Add firmware for Cirrus CS35L54 for some HP laptops
* amdgpu: Revert sienna cichlid dmcub firmware update
* iwlwifi: add Bz FW for core89-58 release
* rtl_nic: add firmware rtl8126a-3
* update MT7921 WiFi/bluetooth device firmware
* amdgpu: update DMCUB to v0.0.232.0 for DCN314 and DCN351
* amdgpu: DMCUB updates forvarious AMDGPU ASICs
* rtw89: 8922a: add fw format-1 v0.35.41.0
* update MT7925 WiFi/bluetooth device firmware
* rtl_bt: Add firmware and config files for RTL8922A
* rtl_bt: Add firmware file for the the RTL8723CS Bluetooth part
* rtl_bt: de-dupe identical config.bin files
* rename rtl8723bs_config-OBDA8723.bin -> rtl_bt/rtl8723bs_config.bin
* Update AMD SEV firmware
* update firmware for MT7996
* Revert 'i915: Update MTL DMC v2.22'
* ath12k: WCN7850 hw2.0: update board-2.bin
* ath11k: WCN6855 hw2.0: update to WLAN.HSP.1.1-03125-QCAHSPSWPL_V1_V2_SILICONZ_LITE-3.6510.41
* ath11k: WCN6855 hw2.0: update board-2.bin
* ath11k: QCA2066 hw2.1: add to WLAN.HSP.1.1-03926.13-QCAHSPSWPL_V2_SILICONZ_CE-2.52297.3
* ath11k: QCA2066 hw2.1: add board-2.bin
* ath11k: IPQ5018 hw1.0: update to WLAN.HK.2.6.0.1-01291-QCAHKSWPL_SILICONZ-1
* qcom: vpu: add video firmware for sa8775p
* amdgpu: DMCUB updates for various AMDGPU ASICs");

  script_tag(name:"affected", value:"'linux-firmware' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"amd-gpu-firmware", rpm:"amd-gpu-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"amd-ucode-firmware", rpm:"amd-ucode-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"atheros-firmware", rpm:"atheros-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"brcmfmac-firmware", rpm:"brcmfmac-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cirrus-audio-firmware", rpm:"cirrus-audio-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dvb-firmware", rpm:"dvb-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"intel-audio-firmware", rpm:"intel-audio-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"intel-gpu-firmware", rpm:"intel-gpu-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"intel-vsc-firmware", rpm:"intel-vsc-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlegacy-firmware", rpm:"iwlegacy-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlwifi-dvm-firmware", rpm:"iwlwifi-dvm-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlwifi-mvm-firmware", rpm:"iwlwifi-mvm-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libertas-firmware", rpm:"libertas-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linux-firmware", rpm:"linux-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linux-firmware-whence", rpm:"linux-firmware-whence~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liquidio-firmware", rpm:"liquidio-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlxsw_spectrum-firmware", rpm:"mlxsw_spectrum-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mrvlprestera-firmware", rpm:"mrvlprestera-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mt7xxx-firmware", rpm:"mt7xxx-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netronome-firmware", rpm:"netronome-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-gpu-firmware", rpm:"nvidia-gpu-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nxpwireless-firmware", rpm:"nxpwireless-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qcom-firmware", rpm:"qcom-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qed-firmware", rpm:"qed-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"realtek-firmware", rpm:"realtek-firmware~20240909~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiwilink-firmware", rpm:"tiwilink-firmware~20240909~1.fc40", rls:"FC40"))) {
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

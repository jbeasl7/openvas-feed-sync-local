# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.516982149925");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-516b214c25)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-516b214c25");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-516b214c25");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-firmware' package(s) announced via the FEDORA-2024-516b214c25 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to upstream 20241210

* Update firmware file for Intel BlazarU core
* amdgpu: numerous firmware updates
* upstream amdnpu firmware
* QCA: Add Bluetooth nvm files for WCN785x
* i915: Update Xe2LPD DMC to v2.24
* cirrus: cs35l56: Add firmware for Cirrus CS35L56 for various Dell laptops
* iwlwifi: add Bz-gf FW for core89-91 release
* QCA: Update Bluetooth WCN785x firmware to 2.0.0-00515-2
* ice: update ice DDP wireless_edge package to 1.3.20.0
* ice: update ice DDP comms package to 1.3.52.0
* ice: update ice DDP package to ice-1.3.41.0
* amdgpu: update DMCUB to v9.0.10.0 for DCN314/DCN351
* Update AMD cpu microcode
* xe: Update GUC to v70.36.0 for BMG, LNL
* i915: Update GUC to v70.36.0 for ADL-P, DG1, DG2, MTL, TGL
* iwlwifi: add Bz-gf FW for core91-69 release
* qcom: venus-5.4: add venus firmware file for qcs615
* qcom: update venus firmware file for SC7280
* QCA: Add 22 bluetooth firmware nvm files for QCA2066
* mediatek MT7921/MT7922: update bluetooth firmware
* update for MT7921/MT7922 WiFi device
* qcom: Add QDU100 firmware image files.
* qcom: Update aic100 firmware files");

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

  if(!isnull(res = isrpmvuln(pkg:"amd-gpu-firmware", rpm:"amd-gpu-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"amd-ucode-firmware", rpm:"amd-ucode-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"atheros-firmware", rpm:"atheros-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"brcmfmac-firmware", rpm:"brcmfmac-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cirrus-audio-firmware", rpm:"cirrus-audio-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dvb-firmware", rpm:"dvb-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"intel-audio-firmware", rpm:"intel-audio-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"intel-gpu-firmware", rpm:"intel-gpu-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"intel-vsc-firmware", rpm:"intel-vsc-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlegacy-firmware", rpm:"iwlegacy-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlwifi-dvm-firmware", rpm:"iwlwifi-dvm-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlwifi-mvm-firmware", rpm:"iwlwifi-mvm-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libertas-firmware", rpm:"libertas-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linux-firmware", rpm:"linux-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linux-firmware-whence", rpm:"linux-firmware-whence~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liquidio-firmware", rpm:"liquidio-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlxsw_spectrum-firmware", rpm:"mlxsw_spectrum-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mrvlprestera-firmware", rpm:"mrvlprestera-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mt7xxx-firmware", rpm:"mt7xxx-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netronome-firmware", rpm:"netronome-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-gpu-firmware", rpm:"nvidia-gpu-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nxpwireless-firmware", rpm:"nxpwireless-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qcom-firmware", rpm:"qcom-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qed-firmware", rpm:"qed-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"realtek-firmware", rpm:"realtek-firmware~20241210~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiwilink-firmware", rpm:"tiwilink-firmware~20241210~1.fc41", rls:"FC41"))) {
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

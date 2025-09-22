# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884869");
  script_cve_id("CVE-2022-27635", "CVE-2022-36351", "CVE-2022-38076", "CVE-2022-40964", "CVE-2022-46329");
  script_tag(name:"creation_date", value:"2023-09-26 01:16:12 +0000 (Tue, 26 Sep 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-17 17:06:23 +0000 (Thu, 17 Aug 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-dd3ebcea25)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-dd3ebcea25");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-dd3ebcea25");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2239141");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2239142");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2239143");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2239144");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2239145");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-firmware' package(s) announced via the FEDORA-2023-dd3ebcea25 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to upstream 20230919 release:

* amd-ucode: Add note on fam19h warnings
* i915: update MTL HuC to version 8.5.4
* amdgpu: update DMCUB to 0.0.183.0 for various AMDGPU ASICs
* qcom: add link to sc8280xp audioreach firmware
* qcom: sm8250: add RB5 sensors DSP firmware
* qcom: Update vpu-1.0 firmware
* qcom: sm8250: update DSP firmware
* qcom: add firmware for the onboard WiFi on qcm2290 / qrb4210
* qcom: add venus firmware files for v6.0
* qcom: add firmware for QRB4210 platforms
* qcom: add firmware for QCM2290 platforms
* qcom: add GPU firmware for QCM2290 / QRB2210
* ath10k/WCN3990: move wlanmdsp to qcom/sdm845
* QCA: Update Bluetooth WCN685x 2.1 firmware to 2.1.0-00605
* Fix carl9170fw shell scripts for shellcheck errors
* i915: Update MTL DMC to v2.16
* Update firmware file for Intel Bluetooth AX200/AX201/AX203/AX210/AX211
* Update firmware for qat_4xxx devices
* Update AMD SEV firmware
* rtw89: 8852b: update fw to v0.29.29.3
* rtw89: 8851b: update fw to v0.29.41.2
* i915: add GSC 102.0.0.1655 for MTL
* cirrus: Add CS35L41 firmware for HP G11 models
* Update AMD cpu microcode
* rtl_bt: Add firmware v2 file for RTL8852C
* Revert 'rtl_bt: Update RTL8852C BT USB firmware to 0x040D_7225'
* cxgb4: Update firmware to revision 1.27.4.0");

  script_tag(name:"affected", value:"'linux-firmware' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"amd-gpu-firmware", rpm:"amd-gpu-firmware~20230919~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"atheros-firmware", rpm:"atheros-firmware~20230919~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"brcmfmac-firmware", rpm:"brcmfmac-firmware~20230919~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dvb-firmware", rpm:"dvb-firmware~20230919~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"intel-gpu-firmware", rpm:"intel-gpu-firmware~20230919~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlegacy-firmware", rpm:"iwlegacy-firmware~20230919~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlwifi-dvm-firmware", rpm:"iwlwifi-dvm-firmware~20230919~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlwifi-mvm-firmware", rpm:"iwlwifi-mvm-firmware~20230919~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libertas-firmware", rpm:"libertas-firmware~20230919~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linux-firmware", rpm:"linux-firmware~20230919~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linux-firmware-whence", rpm:"linux-firmware-whence~20230919~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liquidio-firmware", rpm:"liquidio-firmware~20230919~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlxsw_spectrum-firmware", rpm:"mlxsw_spectrum-firmware~20230919~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mrvlprestera-firmware", rpm:"mrvlprestera-firmware~20230919~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mt7xxx-firmware", rpm:"mt7xxx-firmware~20230919~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netronome-firmware", rpm:"netronome-firmware~20230919~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-gpu-firmware", rpm:"nvidia-gpu-firmware~20230919~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qcom-firmware", rpm:"qcom-firmware~20230919~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"realtek-firmware", rpm:"realtek-firmware~20230919~1.fc39", rls:"FC39"))) {
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

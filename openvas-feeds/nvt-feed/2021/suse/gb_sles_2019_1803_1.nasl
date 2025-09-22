# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1803.1");
  script_cve_id("CVE-2019-9836");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:22 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-03 19:01:00 +0000 (Wed, 03 Jul 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1803-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1803-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191803-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-firmware' package(s) announced via the SUSE-SU-2019:1803-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kernel-firmware fixes the following issues:

kernel-firmware was updated to version 20190618:
cavium: Add firmware for CNN55XX crypto driver.

linux-firmware: Update firmware file for Intel Bluetooth 22161

linux-firmware: Update firmware file for Intel Bluetooth 9560

linux-firmware: Update firmware file for Intel Bluetooth 9260

linux-firmware: Update AMD SEV firmware (CVE-2019-9836, bsc#1139383)

linux-firmware: update licence text for Marvell firmware

linux-firmware: update firmware for mhdp8546

linux-firmware: rsi: update firmware images for Redpine 9113 chipset

imx: sdma: update firmware to v3.5/v4.5

nvidia: update GP10[2467] SEC2 RTOS with the one already used on GP108

linux-firmware: Update firmware file for Intel Bluetooth 8265

linux-firmware: Update firmware file for Intel Bluetooth 9260

linux-firmware: Update firmware file for Intel Bluetooth 9560

amlogic: add video decoder firmwares

iwlwifi: update -46 firmwares for 22260 and 9000 series

iwlwifi: add firmware for 22260 and update 9000 series -46 firmwares

iwlwifi: add -46.ucode firmwares for 9000 series

amdgpu: update vega20 to the latest 19.10 firmware

amdgpu: update vega12 to the latest 19.10 firmware

amdgpu: update vega10 to the latest 19.10 firmware

amdgpu: update polaris11 to the latest 19.10 firmware

amdgpu: update polaris10 to the latest 19.10 firmware

amdgpu: update raven2 to the latest 19.10 firmware

amdgpu: update raven to the latest 19.10 firmware

amdgpu: update picasso to the latest 19.10 firmware

linux-firmware: update fw for qat devices

Mellanox: Add new mlxsw_spectrum firmware 13.2000.1122

drm/i915/firmware: Add ICL HuC v8.4.3238

drm/i915/firmware: Add ICL GuC v32.0.3

drm/i915/firmware: Add GLK HuC v03.01.2893

drm/i915/firmware: Add GLK GuC v32.0.3

drm/i915/firmware: Add KBL GuC v32.0.3

drm/i915/firmware: Add SKL GuC v32.0.3

drm/i915/firmware: Add BXT GuC v32.0.3

linux-firmware: Add firmware file for Intel Bluetooth 22161

cxgb4: update firmware to revision 1.23.4.0 (bsc#1136334)

linux-firmware: Update NXP Management Complex firmware to version 10.14.3

linux-firmware: add firmware for MT7615E

mediatek: update MT8173 VPU firmware to v1.1.2 [decoder] Enlarge struct
 vdec_pic_info to support more capture buffer plane and capture buffer
 format change.

linux-firmware: update Marvell 8797/8997 firmware images

nfp: update Agilio SmartNIC flower firmware to rev AOTC-2.10.A.23");

  script_tag(name:"affected", value:"'kernel-firmware' package(s) on SUSE Linux Enterprise Module for Basesystem 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~20190618~3.22.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-amd", rpm:"ucode-amd~20190618~3.22.1", rls:"SLES15.0"))) {
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

# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.853773");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2019-14584");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-11 16:22:00 +0000 (Fri, 11 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-04-24 03:04:04 +0000 (Sat, 24 Apr 2021)");
  script_name("openSUSE: Security Advisory for shim (openSUSE-SU-2021:0598-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0598-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/O2IF5TPLLS7U2RNC42HXIHTRUMS4Q6YV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'shim'
  package(s) announced via the openSUSE-SU-2021:0598-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for shim fixes the following issues:

  - Updated openSUSE x86 signature

  - Avoid the error message during linux system boot (boo#1184454)

  - Prevent the build id being added to the binary. That can cause issues
       with the signature

     Update to 15.4 (boo#1182057)

     + Rename the SBAT variable and fix the self-check of SBAT
     + sbat: add more dprint()
     + arm/aa64: Swizzle some sections to make old sbsign happier
     + arm/aa64 targets: put .rel* and .dyn* in .rodata

  - Change the SBAT variable name and enhance the handling of SBAT
       (boo#1182057)

     Update to 15.3 for SBAT support (boo#1182057)

     + Drop gnu-efi from BuildRequires since upstream pull it into the

  - Generate vender-specific SBAT metadata
       + Add dos2unix to BuildRequires since Makefile requires it for vendor
         SBAT

  - Update dbx-cert.tar.xz and vendor-dbx.bin to block the following sign
       keys:
       + SLES-UEFI-SIGN-Certificate-2020-07.crt
       + openSUSE-UEFI-SIGN-Certificate-2020-07.crt

  - Check CodeSign in the signer&#x27 s EKU (boo#1177315)

  - Fixed NULL pointer dereference in AuthenticodeVerify() (boo#1177789,
       CVE-2019-14584)

  - All newly released openSUSE kernels enable kernel lockdown and signature
       verification, so there is no need to add the prompt anymore.

  - shim-install: Support changing default shim efi binary in
       /usr/etc/default/shim and /etc/default/shim (boo#1177315)");

  script_tag(name:"affected", value:"'shim' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"shim", rpm:"shim~15.4~lp152.4.8.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shim-debuginfo", rpm:"shim-debuginfo~15.4~lp152.4.8.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shim-debugsource", rpm:"shim-debugsource~15.4~lp152.4.8.1", rls:"openSUSELeap15.2"))) {
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
# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833901");
  script_version("2025-03-12T05:38:19+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-12 05:38:19 +0000 (Wed, 12 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-03-04 08:01:00 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for pipewire (SUSE-SU-2023:3256-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3256-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2QPJN7AQI7YWI2E3UTT5LVPMACJCNDIK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pipewire'
  package(s) announced via the SUSE-SU-2023:3256-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pipewire fixes the following security issues:

  * Fixed issue where an app which only has permission to access one stream can
      also access other streams (bsc#1213682).

  Bugfixes:

  - Fixed division by 0 and other issues with invalid values (glfo#pipewire/pipewire#2953)

  - Fixed an overflow resulting in choppy sound in some cases (glfo#pipewire/pipewire#2680)");

  script_tag(name:"affected", value:"'pipewire' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpipewire-0_3-0", rpm:"libpipewire-0_3-0~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire", rpm:"pipewire~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-modules-0_3", rpm:"pipewire-modules-0_3~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-libjack-0_3-debuginfo", rpm:"pipewire-libjack-0_3-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-alsa-debuginfo", rpm:"pipewire-alsa-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-pulseaudio-debuginfo", rpm:"pipewire-pulseaudio-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-plugins-0_2-debuginfo", rpm:"pipewire-spa-plugins-0_2-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-plugins-0_2", rpm:"pipewire-spa-plugins-0_2~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-doc", rpm:"pipewire-doc~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-tools", rpm:"pipewire-spa-tools~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpipewire-0_3-0-debuginfo", rpm:"libpipewire-0_3-0-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-alsa", rpm:"pipewire-alsa~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-modules-0_3-debuginfo", rpm:"pipewire-modules-0_3-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-devel", rpm:"pipewire-devel~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-tools", rpm:"pipewire-tools~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-pulseaudio", rpm:"pipewire-pulseaudio~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugin-pipewire-debuginfo", rpm:"gstreamer-plugin-pipewire-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-debugsource", rpm:"pipewire-debugsource~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugin-pipewire", rpm:"gstreamer-plugin-pipewire~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-libjack-0_3", rpm:"pipewire-libjack-0_3~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-tools-debuginfo", rpm:"pipewire-spa-tools-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-debuginfo", rpm:"pipewire-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-libjack-0_3-devel", rpm:"pipewire-libjack-0_3-devel~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-tools-debuginfo", rpm:"pipewire-tools-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-modules-0_3-32bit-debuginfo", rpm:"pipewire-modules-0_3-32bit-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpipewire-0_3-0-32bit-debuginfo", rpm:"libpipewire-0_3-0-32bit-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-modules-0_3-32bit", rpm:"pipewire-modules-0_3-32bit~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-libjack-0_3-32bit", rpm:"pipewire-libjack-0_3-32bit~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-plugins-0_2-32bit-debuginfo", rpm:"pipewire-spa-plugins-0_2-32bit-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-alsa-32bit-debuginfo", rpm:"pipewire-alsa-32bit-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-libjack-0_3-32bit-debuginfo", rpm:"pipewire-libjack-0_3-32bit-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-plugins-0_2-32bit", rpm:"pipewire-spa-plugins-0_2-32bit~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpipewire-0_3-0-32bit", rpm:"libpipewire-0_3-0-32bit~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-alsa-32bit", rpm:"pipewire-alsa-32bit~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-lang", rpm:"pipewire-lang~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-plugins-0_2-64bit", rpm:"pipewire-spa-plugins-0_2-64bit~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-libjack-0_3-64bit", rpm:"pipewire-libjack-0_3-64bit~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-modules-0_3-64bit", rpm:"pipewire-modules-0_3-64bit~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-libjack-0_3-64bit-debuginfo", rpm:"pipewire-libjack-0_3-64bit-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-plugins-0_2-64bit-debuginfo", rpm:"pipewire-spa-plugins-0_2-64bit-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-alsa-64bit-debuginfo", rpm:"pipewire-alsa-64bit-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpipewire-0_3-0-64bit-debuginfo", rpm:"libpipewire-0_3-0-64bit-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-alsa-64bit", rpm:"pipewire-alsa-64bit~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpipewire-0_3-0-64bit", rpm:"libpipewire-0_3-0-64bit~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-modules-0_3-64bit-debuginfo", rpm:"pipewire-modules-0_3-64bit-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpipewire-0_3-0", rpm:"libpipewire-0_3-0~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire", rpm:"pipewire~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-modules-0_3", rpm:"pipewire-modules-0_3~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-libjack-0_3-debuginfo", rpm:"pipewire-libjack-0_3-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-alsa-debuginfo", rpm:"pipewire-alsa-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-pulseaudio-debuginfo", rpm:"pipewire-pulseaudio-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-plugins-0_2-debuginfo", rpm:"pipewire-spa-plugins-0_2-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-plugins-0_2", rpm:"pipewire-spa-plugins-0_2~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-doc", rpm:"pipewire-doc~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-tools", rpm:"pipewire-spa-tools~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpipewire-0_3-0-debuginfo", rpm:"libpipewire-0_3-0-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-alsa", rpm:"pipewire-alsa~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-modules-0_3-debuginfo", rpm:"pipewire-modules-0_3-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-devel", rpm:"pipewire-devel~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-tools", rpm:"pipewire-tools~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-pulseaudio", rpm:"pipewire-pulseaudio~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugin-pipewire-debuginfo", rpm:"gstreamer-plugin-pipewire-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-debugsource", rpm:"pipewire-debugsource~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugin-pipewire", rpm:"gstreamer-plugin-pipewire~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-libjack-0_3", rpm:"pipewire-libjack-0_3~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-tools-debuginfo", rpm:"pipewire-spa-tools-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-debuginfo", rpm:"pipewire-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-libjack-0_3-devel", rpm:"pipewire-libjack-0_3-devel~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-tools-debuginfo", rpm:"pipewire-tools-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-modules-0_3-32bit-debuginfo", rpm:"pipewire-modules-0_3-32bit-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpipewire-0_3-0-32bit-debuginfo", rpm:"libpipewire-0_3-0-32bit-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-modules-0_3-32bit", rpm:"pipewire-modules-0_3-32bit~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-libjack-0_3-32bit", rpm:"pipewire-libjack-0_3-32bit~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-plugins-0_2-32bit-debuginfo", rpm:"pipewire-spa-plugins-0_2-32bit-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-alsa-32bit-debuginfo", rpm:"pipewire-alsa-32bit-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-libjack-0_3-32bit-debuginfo", rpm:"pipewire-libjack-0_3-32bit-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-plugins-0_2-32bit", rpm:"pipewire-spa-plugins-0_2-32bit~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpipewire-0_3-0-32bit", rpm:"libpipewire-0_3-0-32bit~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-alsa-32bit", rpm:"pipewire-alsa-32bit~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-lang", rpm:"pipewire-lang~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-plugins-0_2-64bit", rpm:"pipewire-spa-plugins-0_2-64bit~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-libjack-0_3-64bit", rpm:"pipewire-libjack-0_3-64bit~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-modules-0_3-64bit", rpm:"pipewire-modules-0_3-64bit~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-libjack-0_3-64bit-debuginfo", rpm:"pipewire-libjack-0_3-64bit-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-plugins-0_2-64bit-debuginfo", rpm:"pipewire-spa-plugins-0_2-64bit-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-alsa-64bit-debuginfo", rpm:"pipewire-alsa-64bit-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpipewire-0_3-0-64bit-debuginfo", rpm:"libpipewire-0_3-0-64bit-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-alsa-64bit", rpm:"pipewire-alsa-64bit~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpipewire-0_3-0-64bit", rpm:"libpipewire-0_3-0-64bit~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-modules-0_3-64bit-debuginfo", rpm:"pipewire-modules-0_3-64bit-debuginfo~0.3.49~150400.3.3.1", rls:"openSUSELeap15.4"))) {
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

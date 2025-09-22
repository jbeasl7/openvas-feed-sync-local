# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802179");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_name("Mozilla Products Detection (Mac OS X SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_family("Product detection");
  script_mandatory_keys("ssh/login/osx_name");

  script_tag(name:"summary", value:"SSH login-based detection of Mozilla products.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("cpe.inc");
include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

if(!get_kb_item("ssh/login/osx_name")) {
  close(sock);
  exit(0);
}

ffVerCmd = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/Firefox.app/Contents/Info CFBundleShortVersionString"));
if(strlen(ffVerCmd) > 0 && "does not exist" >!< ffVerCmd) {

  ffVer = eregmatch(pattern:"([0-9.]+)([a-zA-Z0-9]+)?", string:ffVerCmd);
  if(!isnull(ffVer[1])) {
    if(!isnull(ffVer[2])) {
      ffVer = ffVer[1] + "." + ffVer[2];
    } else {
      ffVer = ffVer[1];
    }
  }

  if(ffVer) {
    key_list = make_list("/Applications/Firefox.app/Contents/MacOS", "/Applications/Firefox.app/Contents/Resources");
    foreach dir(key_list) {

      esrFile = ssh_find_file(file_name:dir + "/update-settings\.ini$", useregex:TRUE, sock:sock);
      if(esrFile) {
        foreach binaryName(esrFile) {

          binaryName = chomp(binaryName);
          if(!binaryName)
            continue;

          isFfEsr = ssh_get_bin_version(full_prog_name:"cat", sock:sock, version_argv:binaryName, ver_pattern:"mozilla-esr");
          if(isFfEsr)
            break;
        }
      }
    }

    set_kb_item(name:"mozilla/firefox/macosx/detected", value:TRUE);
    set_kb_item(name:"mozilla/firefox/linux_macosx/detected", value:TRUE);
    set_kb_item(name:"mozilla/firefox/windows_macosx/detected", value:TRUE);
    set_kb_item(name:"mozilla/firefox/windows_linux_macosx/detected", value:TRUE);
    set_kb_item(name:"mozilla/firefox/detected", value:TRUE);

    if(isFfEsr) {
      set_kb_item(name:"Mozilla/Firefox-ESR/MacOSX/Version", value:ffVer);
      set_kb_item(name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed", value:TRUE);
      register_and_report_cpe(app:"Mozilla Firefox ESR", ver:ffVer, base:"cpe:/a:mozilla:firefox_esr:", expr:"^([0-9.]+)([a-zA-Z0-9]+)?", insloc:"/Applications/Firefox.app", concluded:ffVerCmd, regPort:0, regService:"ssh-login");
    } else {
      set_kb_item(name:"Mozilla/Firefox/MacOSX/Version", value:ffVer);
      set_kb_item(name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed", value:TRUE);
      register_and_report_cpe(app:"Mozilla Firefox", ver:ffVer, base:"cpe:/a:mozilla:firefox:", expr:"^([0-9.]+)([a-zA-Z0-9]+)?", insloc:"/Applications/Firefox.app", concluded:ffVerCmd, regPort:0, regService:"ssh-login");
    }
  }
}

smVerCmd = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/SeaMonkey.app/Contents/Info CFBundleShortVersionString"));
if(strlen(smVerCmd) > 0 && "does not exist" >!< smVerCmd) {

  smVer = eregmatch(pattern:"([0-9.]+)([a-zA-Z0-9]+)?", string:smVerCmd);
  if(!isnull(smVer[1])) {
    if(!isnull(smVer[2])) {
      smVer = smVer[1] + "." + smVer[2];
    } else {
      smVer = smVer[1];
    }
  }

  set_kb_item(name:"SeaMonkey/MacOSX/Version", value:smVer);
  set_kb_item(name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed", value:TRUE);
  register_and_report_cpe(app:"Mozilla SeaMonkey", ver:smVer, base:"cpe:/a:mozilla:seamonkey:", expr:"^([0-9.]+)([a-zA-Z0-9]+)?", insloc:"/Applications/SeaMonkey.app", concluded:smVerCmd, regPort:0, regService:"ssh-login");
}

tbVerCmd = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/Thunderbird.app/Contents/Info CFBundleShortVersionString"));
if(strlen(tbVerCmd) > 0 && "does not exist" >!< tbVerCmd) {

  tbVer = eregmatch(pattern:"([0-9.]+)([a-zA-Z0-9]+)?", string:tbVerCmd);
  if(!isnull(tbVer[1])) {
    if(!isnull(tbVer[2])) {
      tbVer = tbVer[1] + "." + tbVer[2];
    } else {
      tbVer = tbVer[1];
    }
  }

  if(tbVer) {
    thuFile = ssh_find_file(file_name:"/Applications/Thunderbird\.app/Contents/MacOS/update-settings\.ini$", useregex:TRUE, sock:sock);
    if(thuFile) {
      foreach binaryName (thuFile) {

        binaryName = chomp(binaryName);
        if(!binaryName)
          continue;

        isTbEsr = ssh_get_bin_version(full_prog_name:"cat", sock:sock, version_argv:binaryName, ver_pattern:"comm-esr");
        if(isTbEsr)
          break;
      }
    }

    if(isTbEsr) {
      set_kb_item(name:"Thunderbird-ESR/MacOSX/Version", value:tbVer);
      set_kb_item(name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed", value:TRUE);
      register_and_report_cpe(app:"Mozilla Thunderbird ESR", ver:tbVer, base:"cpe:/a:mozilla:thunderbird_esr:", expr:"^([0-9.]+)([a-zA-Z0-9]+)?", insloc:"/Applications/Thunderbird.app", concluded:tbVerCmd, regPort:0, regService:"ssh-login");
    } else {
      set_kb_item(name:"Thunderbird/MacOSX/Version", value:tbVer);
      set_kb_item(name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed", value:TRUE);
      register_and_report_cpe(app:"Mozilla Thunderbird", ver:tbVer, base:"cpe:/a:mozilla:thunderbird:", expr:"^([0-9.]+)([a-zA-Z0-9]+)?", insloc:"/Applications/Thunderbird.app", concluded:tbVerCmd, regPort:0, regService:"ssh-login");
    }
  }
}

close(sock);
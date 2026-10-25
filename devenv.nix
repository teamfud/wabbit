{
  pkgs,
  lib,
  config,
  inputs,
  ...
}:

{

  #
  # https://devenv.sh/packages/
  packages = [ pkgs.git pkgs.sops pkgs.age ];
  dotenv.enable = true;

  # disable mcp


  # https://devenv.sh/languages/
  # languages.rust.enable = true;

  # https://devenv.sh/processes/
  # processes.dev.exec = "${lib.getExe pkgs.watchexec} -n -- ls -la";

  # https://devenv.sh/services/
  # services.postgres.enable = true;

  # https://devenv.sh/scripts/

  # https://devenv.sh/git-hooks/
  # git-hooks.hooks.shellcheck.enable = true;

  # See full reference at https://devenv.sh/reference/options/
}
